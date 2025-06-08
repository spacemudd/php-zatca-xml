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
     * @return self
     */
    public static function signInvoice(string $xmlInvoice, Certificate $certificate): self
    {
        $instance = new self();
        $instance->certificate = $certificate;

        // Convert XML string to DOM
        $xmlDom = InvoiceExtension::fromString($xmlInvoice);

        // Remove unwanted tags per guidelines
        $xmlDom->removeByXpath('ext:UBLExtensions');
        $xmlDom->removeByXpath('cac:Signature');
        $xmlDom->removeParentByXpath('cac:AdditionalDocumentReference/cbc:ID[. = "QR"]');

        // Compute hash using SHA-256
        $invoiceHashBinary = hash('sha256', $xmlDom->getElement()->C14N(true, false), true);
        $invoiceHashBase64 = base64_encode($invoiceHashBinary);

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

        // Generate QR Code
        $instance->qrCode = QRCodeGenerator::createFromTags(
            $xmlDom->generateQrTagsArray($certificate, $invoiceHashBase64, $instance->digitalSignature)
        )->encodeBase64();

        // Insert UBL extensions and QR code into original XML
        $finalSignedXml = self::insertExtensionsAndQr($xmlInvoice, $ublExtension, $instance->qrCode);
        $instance->signedInvoice = $finalSignedXml;

        // Calculate FINAL invoice hash exactly like ZATCA will:
        $instance->hash = self::calculateZatcaInvoiceHash($finalSignedXml);

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
     * @param string $signedXml
     * @return string
     */
    private static function calculateZatcaInvoiceHash(string $signedXml): string
    {
        $doc = new \DOMDocument();
        //$doc->preserveWhiteSpace = false; // ZATCA compliance fails if this is true.
        $doc->formatOutput = false;
        $doc->loadXML($signedXml);

        $xpath = new \DOMXPath($doc);
        $xpath->registerNamespace('ext', 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2');
        $xpath->registerNamespace('cac', 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2');
        $xpath->registerNamespace('cbc', 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2');

        $nodesToRemove = [
            '//ext:UBLExtensions',
            '//cac:Signature',
            '//cac:AdditionalDocumentReference[cbc:ID="QR"]'
        ];

        foreach ($nodesToRemove as $query) {
            $nodes = $xpath->query($query);
            foreach ($nodes as $node) {
                $node->parentNode->removeChild($node);
            }
        }

        $canonical = $doc->C14N(false, false); // exclusive being true will fail compliance test.
        return base64_encode(hash('sha256', $canonical, true));
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
