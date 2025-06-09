<?php

namespace Saleh7\Zatca;

use Saleh7\Zatca\Exceptions\ZatcaStorageException;
use Saleh7\Zatca\Helpers\QRCodeGenerator;
use Saleh7\Zatca\Helpers\Certificate;
use Saleh7\Zatca\Helpers\InvoiceExtension;
use Saleh7\Zatca\Helpers\InvoiceSignatureBuilder;

class InvoiceSigner
{
    private $signedInvoice;  // Signed invoice XML string
    private $hash;           // Invoice hash (base64 encoded)
    private $qrCode;         // QR Code (base64 encoded)
    private $certificate;    // Certificate used for signing
    private $digitalSignature; // Digital signature (base64 encoded)

    // Private constructor to force usage of signInvoice method
    private function __construct() {}

    /**
     * Signs the invoice XML and returns an InvoiceSigner object.
     *
     * @param string      $xmlInvoice  Invoice XML as a string
     * @param Certificate $certificate Certificate for signing
     * @param bool        $isSimplified Whether this is a simplified invoice
     * @return self
     */
    public static function signInvoice(string $xmlInvoice, Certificate $certificate, bool $isSimplified = false): self
    {
        $instance = new self();
        $instance->certificate = $certificate;

        // Convert XML string to DOM
        $xmlDom = InvoiceExtension::fromString($xmlInvoice);
        
        // Always determine if this is a simplified invoice by checking the InvoiceTypeCode
        // This is more reliable than relying on the parameter
        $invoiceTypeCodeNode = $xmlDom->find("cbc:InvoiceTypeCode");
        $detectedIsSimplified = false;
        if ($invoiceTypeCodeNode) {
            $nameAttr = $invoiceTypeCodeNode->getElement()->getAttribute('name');
            $detectedIsSimplified = str_starts_with($nameAttr, "02");
        }
        
        // Use the detected value - it's more reliable than the parameter
        $isSimplified = $detectedIsSimplified;

        // For simplified invoices, we need to use the signed XML hash in the QR code
        // Calculate a temporary hash for QR code generation - this will be updated later
        $invoiceHashBase64 = self::calculateCleanInvoiceHash($xmlInvoice, $isSimplified);
        $invoiceHashBinary = base64_decode($invoiceHashBase64);

        // Create digital signature using the private key
        $instance->digitalSignature = base64_encode(
            $certificate->getPrivateKey()->sign($invoiceHashBinary)
        );

        // Prepare UBL Extension with certificate, hash, and signature
        $ublExtension = (new InvoiceSignatureBuilder)
            ->setCertificate($certificate)
            ->setInvoiceDigest($invoiceHashBase64)
            ->setSignatureValue($instance->digitalSignature)
            ->buildSignatureXml();

        // Generate QR Code tags
        $qrTags = $xmlDom->generateQrTagsArray($certificate, $invoiceHashBase64, $instance->digitalSignature);
        
        // Initialize debug info
        $debugInfo = '';
        
        // Debug logging (conditional)
        if (config('zatca.debug_on', false)) {
            $debugInfo = "Invoice Type Code: " . ($isSimplified ? "Simplified (02)" : "Standard (01)") . "\n";
            $debugInfo .= "Calculated Invoice Hash: " . $invoiceHashBase64 . "\n\n";
            $debugInfo .= "QR Code Tags:\n";
            foreach ($qrTags as $index => $tag) {
                $tagId = $tag->getTag();
                $tagValue = $tag->getValue();
                $debugInfo .= "Tag $index (ID: $tagId): " . (is_string($tagValue) ? $tagValue : bin2hex($tagValue)) . "\n";
            }
            file_put_contents(base_path() . '/output/qr_debug.txt', $debugInfo);
        }

        // Generate QR Code - passing the SAME invoiceHashBase64 and signature
        // to ensure consistency between XML hash and QR code hash
        // Pass the isSimplified flag to ensure correct tag ordering for simplified invoices
        $instance->qrCode = QRCodeGenerator::createFromTags(
            $qrTags,
            $isSimplified
        )->encodeBase64();

        // Insert UBL extensions and QR code into original XML
        $finalSignedXml = self::insertExtensionsAndQr($xmlInvoice, $ublExtension, $instance->qrCode);
        $instance->signedInvoice = $finalSignedXml;

        // Calculate FINAL invoice hash exactly like ZATCA will from the signed XML
        // This hash is used when submitting to the ZATCA API
        $finalHashBase64 = self::calculateZatcaInvoiceHash($finalSignedXml, $isSimplified);
        $instance->hash = $finalHashBase64;

        // For simplified invoices, update the QR code with the correct hash from signed XML
        if ($isSimplified && $finalHashBase64 !== $invoiceHashBase64) {
            // Regenerate QR code with the correct signed XML hash
            $correctedQrTags = $xmlDom->generateQrTagsArray($certificate, $finalHashBase64, $instance->digitalSignature);
            $instance->qrCode = QRCodeGenerator::createFromTags($correctedQrTags, $isSimplified)->encodeBase64();
            
            // Regenerate the final signed XML with the corrected QR code
            $instance->signedInvoice = self::insertExtensionsAndQr($xmlInvoice, $ublExtension, $instance->qrCode);
            
            // Debug logging (conditional)
            if (config('zatca.debug_on', false)) {
                $debugInfo .= "\nUpdated QR Code Hash for Simplified Invoice: " . $finalHashBase64 . "\n";
            }
        }

        // Debug logging (conditional)
        if (config('zatca.debug_on', false)) {
            $debugInfo .= "\nFinal Invoice Hash: " . $instance->hash . "\n";
            file_put_contents(base_path() . '/output/qr_debug.txt', $debugInfo);
        }

        return $instance;
    }

    /**
     * @param string $xmlInvoice
     * @param string $ublExtension
     * @param string $qrCode
     * @return string
     */
    private static function insertExtensionsAndQr(string $xmlInvoice, string $ublExtension, string $qrCode): string
    {
        // Insert into XML by string replacement (same as your original logic)
        $signedInvoice = str_replace(
            [
                '<cbc:ProfileID>',
                '<cac:AccountingSupplierParty>'],
            [
                "<ext:UBLExtensions>$ublExtension</ext:UBLExtensions>\n    <cbc:ProfileID>",
                self::getQRNode($qrCode) . "\n    <cac:AccountingSupplierParty>"
            ],
            $xmlInvoice
        );

        return preg_replace('/^[ \t]*[\r\n]+/m', '', $signedInvoice);
    }

    /**
     * Calculate the clean invoice hash from raw XML (before signing)
     * This method ensures consistent hash calculation for both QR code and API submission
     * 
     * @param string $xmlInvoice The raw XML invoice string
     * @param bool $isSimplified Whether this is a simplified invoice
     * @return string Base64-encoded SHA-256 hash
     */
    private static function calculateCleanInvoiceHash(string $xmlInvoice, bool $isSimplified = false): string
    {
        // Parse the XML to remove elements
        $cleanDoc = new \DOMDocument();
        $cleanDoc->loadXML($xmlInvoice);
        
        // Remove elements that shouldn't be included in hash calculation
        $cleanXPath = new \DOMXPath($cleanDoc);
        $cleanXPath->registerNamespace('ext', 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2');
        $cleanXPath->registerNamespace('cac', 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2');
        $cleanXPath->registerNamespace('cbc', 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2');
        
        // Remove UBL Extensions (if any)
        $extensions = $cleanXPath->query('//ext:UBLExtensions');
        foreach ($extensions as $extension) {
            $extension->parentNode->removeChild($extension);
        }
        
        // Remove Signature (if any)
        $signatures = $cleanXPath->query('//cac:Signature');
        foreach ($signatures as $signature) {
            $signature->parentNode->removeChild($signature);
        }
        
        // Remove QR references (if any)
        $qrRefs = $cleanXPath->query('//cac:AdditionalDocumentReference[cbc:ID="QR"]');
        foreach ($qrRefs as $qrRef) {
            $qrRef->parentNode->removeChild($qrRef);
        }
        
        // Canonicalize the XML
        $canonicalXml = $cleanDoc->documentElement->C14N(false, false);
        
        // Calculate the hash
        return base64_encode(hash('sha256', $canonicalXml, true));
    }

    /**
     * Calculate the invoice hash according to ZATCA specifications.
     * This method is critical for ensuring that the hash submitted to the ZATCA API
     * matches the hash calculated by ZATCA's validation service.
     * 
     * @param string $signedXml The signed XML string
     * @param bool $isSimplified Whether this is a simplified invoice
     * @return string Base64-encoded SHA-256 hash
     */
    private static function calculateZatcaInvoiceHash(string $signedXml, bool $isSimplified = false): string
    {
        // Always determine if this is a simplified invoice by checking the InvoiceTypeCode
        // This is essential for proper hash calculation
        $doc = new \DOMDocument();
        $doc->loadXML($signedXml);
        $xpath = new \DOMXPath($doc);
        $xpath->registerNamespace('cbc', 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2');
        
        $invoiceTypeCodeNodes = $xpath->query('//cbc:InvoiceTypeCode');
        if ($invoiceTypeCodeNodes->length > 0) {
            $invoiceTypeCode = $invoiceTypeCodeNodes->item(0);
            $nameAttr = $invoiceTypeCode->getAttribute('name');
            $isSimplified = str_starts_with($nameAttr, "02");
        }
        
        // Use the same clean hash calculation method for consistency
        return self::calculateCleanInvoiceHash($signedXml, $isSimplified);
    }

    /**
     * Saves the signed invoice as an XML file.
     *
     * @param string $filename (Optional) File path to save the XML.
     * @param string|null $outputDir (Optional) Directory name. Set to null if $filename contains the full file path.
     * @return self
     * @throws ZatcaStorageException If the XML file cannot be saved.
     */
    public function saveXMLFile(string $filename = 'signed_invoice.xml', ?string $outputDir = 'output'): self
    {
        (new Storage($outputDir))->put($filename, $this->signedInvoice);
        return $this;
    }

    /**
     * Get the signed XML string.
     *
     * @return string
     */
    public function getXML(): string
    {
        return $this->signedInvoice;
    }

    /**
     * Returns the QR node string.
     *
     * @param string $QRCode
     * @return string
     */
    private static function getQRNode(string $QRCode): string
    {
        return "<cac:AdditionalDocumentReference>
            <cbc:ID>QR</cbc:ID>
            <cac:Attachment>
                <cbc:EmbeddedDocumentBinaryObject mimeCode=\"text/plain\">$QRCode</cbc:EmbeddedDocumentBinaryObject>
            </cac:Attachment>
        </cac:AdditionalDocumentReference>
        <cac:Signature>
            <cbc:ID>urn:oasis:names:specification:ubl:signature:Invoice</cbc:ID>
            <cbc:SignatureMethod>urn:oasis:names:specification:ubl:dsig:enveloped:xades</cbc:SignatureMethod>
        </cac:Signature>";
    }

    /**
     * Get signed invoice XML.
     *
     * @return string
     */
    public function getInvoice(): string
    {
        return $this->signedInvoice;
    }

    /**
     * Get invoice hash.
     *
     * @return string
     */
    public function getHash(): string
    {
        return $this->hash;
    }

    /**
     * Get QR Code.
     *
     * @return string
     */
    public function getQRCode(): string
    {
        return $this->qrCode;
    }

    /**
     * Get the certificate used for signing.
     *
     * @return Certificate
     */
    public function getCertificate(): Certificate
    {
        return $this->certificate;
    }
}
