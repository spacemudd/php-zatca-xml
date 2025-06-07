<?php

namespace Saleh7\Zatca;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Http\Message\ResponseInterface;
use Saleh7\Zatca\Api\ComplianceCertificateResult;
use Saleh7\Zatca\Api\ProductionCertificateResult;
use Saleh7\Zatca\Exceptions\ZatcaApiException;
use InvalidArgumentException;
use Saleh7\Zatca\Exceptions\ZatcaStorageException;

/**
 * ZATCA E-Invoicing API Client for compliance and reporting operations.
 */
class ZatcaAPI
{
    private const ENVIRONMENTS = [
        'sandbox'    => 'https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal',
        'simulation' => 'https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation',
        'production' => 'https://gw-fatoora.zatca.gov.sa/e-invoicing/core',
    ];

    private const API_VERSION = 'V2';
    private const SUCCESS_STATUS_CODES = [200, 202];

    private ClientInterface $httpClient;
    private bool $allowWarnings = false;
    private string $environment;

    /**
     * @param string $environment API environment (sandbox|simulation|production)
     * @param ClientInterface|null $client Optional HTTP client to enable dependency injection.
     * @throws InvalidArgumentException For invalid environment.
     */
    public function __construct(string $environment = 'sandbox', ?ClientInterface $client = null)
    {
        if (!isset(self::ENVIRONMENTS[$environment])) {
            $validEnvs = implode(', ', array_keys(self::ENVIRONMENTS));
            throw new InvalidArgumentException("Invalid environment. Valid options: $validEnvs");
        }
        $this->environment = $environment;
        $this->httpClient  = $client ?? new Client([
            'base_uri' => $this->getBaseUri(),
            'timeout'  => 30,
            'verify'   => true,
        ]);
    }

    /**
     * Returns the base URI for the current environment.
     *
     * @return string
     */
    public function getBaseUri(): string
    {
        return self::ENVIRONMENTS[$this->environment];
    }

    /**
     * Load CSR file content.
     *
     * @param string $path File path of the CSR.
     * @return string CSR content.
     * @throws \Exception If file is not found or unreadable.
     */
    public function loadCSRFromFile(string $path): string
    {
        if (!file_exists($path)) {
            throw new \Exception("File not found: {$path}");
        }
        $content = file_get_contents($path);
        if ($content === false) {
            throw new \Exception("Could not read file: {$path}");
        }
        return $content;
    }

    /**
     * Enable/disable acceptance of warning responses.
     */
    public function setWarningHandling(bool $allow): void
    {
        $this->allowWarnings = $allow;
    }

    /**
     * Request compliance certificate using CSR and OTP.
     *
     * @param string $csr CSR content.
     * @param string $otp One-Time Password.
     * @return ComplianceCertificateResult
     * @throws ZatcaApiException For API communication errors.
     */
    public function requestComplianceCertificate(string $csr, string $otp): ComplianceCertificateResult
    {
        try {
            $response = $this->sendRequest(
                'POST',
                '/compliance',
                [
                    'OTP' => $otp,
                    'Accept' => '*/*'  // Accept any content type
                ],
                ['csr' => base64_encode($csr)]
            );

            // Handle both JSON and binary responses
            $certificate = $response['binarySecurityToken'] ?? '';
            $secret = $response['secret'] ?? '';
            $requestId = $response['requestID'] ?? '';

            if (empty($certificate) || empty($secret)) {
                throw new ZatcaApiException(
                    'Invalid compliance certificate response: missing required fields',
                    0,
                    json_encode($response)
                );
            }

            return new ComplianceCertificateResult(
                $this->formatCertificate($certificate),
                $secret,
                $requestId
            );
        } catch (ZatcaApiException $e) {
            // Just rethrow the original exception
            throw $e;
        } catch (\Exception $e) {
            // Wrap other exceptions
            throw new ZatcaApiException(
                'Failed to request compliance certificate: ' . $e->getMessage(),
                0,
                '',
                $e
            );
        }
    }

    /**
     * Validate invoice compliance with ZATCA regulations.
     *
     * @param string $certificate The certificate for authentication.
     * @param string $secret      API secret.
     * @param string $signedInvoice Signed invoice content.
     * @param string $invoiceHash Invoice hash.
     * @param string $uuid      Unique invoice identifier.
     * @return array API response data.
     * @throws ZatcaApiException For API communication errors.
     */
    public function validateInvoiceCompliance(
        string $certificate,
        string $secret,
        string $signedInvoice,
        string $invoiceHash,
        string $uuid
    ): array {
        try {
            return $this->sendRequest(
                'POST',
                '/compliance/invoices',
                ['Accept-Language' => 'en', 'Content-Type' => 'application/json'],
                [
                    'invoiceHash' => $invoiceHash,
                    'uuid'        => $uuid,
                    'invoice'     => base64_encode($signedInvoice),
                ],
                $this->createAuthHeaders($certificate, $secret)
            );
        } catch (ZatcaApiException $e) {
            // يمكن إضافة منطق لمعالجة التحذيرات هنا إذا لزم الأمر.
            throw $e;
        }
    }

    /**
     * Request production certificate using compliance credentials.
     *
     * @param string $certificate         The certificate for authentication.
     * @param string $secret              API secret.
     * @param string $complianceRequestId Compliance request ID.
     * @return ProductionCertificateResult
     * @throws ZatcaApiException For API communication errors.
     */
    public function requestProductionCertificate(
        string $certificate,
        string $secret,
        string $complianceRequestId
    ): ProductionCertificateResult {
        $response = $this->sendRequest(
            'POST',
            '/production/csids',
            ['Content-Type' => 'application/json'],
            ['compliance_request_id' => $complianceRequestId],
            $this->createAuthHeaders($certificate, $secret)
        );

        return new ProductionCertificateResult(
            $this->formatCertificate($response['binarySecurityToken'] ?? ''),
            $response['secret'] ?? '',
            $response['requestID'] ?? ''
        );
    }

    /**
     * Submit invoice for clearance reporting.
     *
     * @param string $certificate  The certificate for authentication.
     * @param string $secret       API secret.
     * @param string $signedInvoice Signed invoice content.
     * @param string $invoiceHash  Invoice hash.
     * @param string $egsUuid      Unique invoice identifier.
     * @return array API response data.
     * @throws ZatcaApiException For API communication errors.
     */
    public function submitClearanceInvoice(
        string $certificate,
        string $secret,
        string $signedInvoice,
        string $invoiceHash,
        string $egsUuid
    ): array {
        return $this->sendRequest(
            'POST',
            '/invoices/clearance/single',
            ['Clearance-Status' => '1', 'Accept-Language' => 'en'],
            [
                'invoiceHash' => $invoiceHash,
                'uuid'        => $egsUuid,
                'invoice'     => base64_encode($signedInvoice),
            ],
            $this->createAuthHeaders($certificate, $secret)
        );
    }

    /**
     * Submit simplified invoice for reporting.
     *
     * @param string $certificate  The certificate for authentication.
     * @param string $secret       API secret.
     * @param string $signedInvoice Signed invoice content.
     * @param string $invoiceHash  Invoice hash.
     * @param string $uuid      Unique invoice identifier.
     * @return array API response data.
     * @throws ZatcaApiException For API communication errors.
     */
    public function submitReportInvoice(
        string $certificate,
        string $secret,
        string $signedInvoice,
        string $invoiceHash,
        string $uuid,
    ): array {
        return $this->sendRequest(
            'POST',
            '/invoices/reporting/single',
            ['Clearance-Status' => '1', 'Accept-Language' => 'en'],
            [
                'invoiceHash' => $invoiceHash,
                'uuid'        => $uuid,
                'invoice'     => base64_encode($signedInvoice),
            ],
            $this->createAuthHeaders($certificate, $secret)
        );
    }

    /**
     * Generate authentication headers for secured endpoints.
     *
     * @param string $certificate
     * @param string $secret
     * @return array
     */
    private function createAuthHeaders(string $certificate, string $secret): array
    {
        $cleanCert   = trim($certificate);
        $credentials = base64_encode($cleanCert . ':' . $secret);
        return ['Authorization' => 'Basic ' . $credentials];
    }

    /**
     * Core request handling with Guzzle.
     *
     * @param string $method HTTP method.
     * @param string $endpoint API endpoint.
     * @param array $headers Additional headers.
     * @param array $payload Request payload.
     * @param array $authHeaders Optional auth headers.
     * @return array Decoded response data.
     * @throws ZatcaApiException On HTTP or API errors.
     */
    private function sendRequest(
        string $method,
        string $endpoint,
        array $headers = [],
        array $payload = [],
        array $authHeaders = []
    ): array {
        try {
            $mergedHeaders = array_merge(
                [
                    'Accept-Version' => self::API_VERSION,
                    'Accept'         => 'application/json',
                ],
                $headers,
                $authHeaders
            );

            $options = [
                'headers' => $mergedHeaders,
                'json'    => $payload,
                'http_errors' => false, // Don't throw exceptions for HTTP errors
                'debug' => true, // Enable debug output
            ];

            // Log request details
            error_log("ZATCA Request - URL: " . $this->getBaseUri() . $endpoint);
            error_log("ZATCA Request - Headers: " . json_encode($mergedHeaders));
            error_log("ZATCA Request - Payload: " . json_encode($payload));

            // Use the base URI from the current environment
            $url = $this->getBaseUri() . $endpoint;
            
            $response = $this->httpClient->request($method, $url, $options);
            $statusCode = $response->getStatusCode();
            
            // Log response details
            error_log("ZATCA Response - Status Code: " . $statusCode);
            error_log("ZATCA Response - Headers: " . json_encode($response->getHeaders()));
            
            $body = (string) $response->getBody();
            error_log("ZATCA Response - Body: " . $body);
            
            // Reset body pointer
            $response->getBody()->rewind();

            // If it's not a success response, throw an exception with the full response
            if (!$this->isSuccessfulResponse($statusCode)) {
                throw new ZatcaApiException(
                    "ZATCA API request failed with status {$statusCode}",
                    $statusCode,
                    $body
                );
            }

            return $this->parseResponse($response);
        } catch (GuzzleException $e) {
            $response = $e->getResponse();
            $body = $response ? (string) $response->getBody() : '';
            $code = $response ? $response->getStatusCode() : 0;
            
            error_log("ZATCA Error - Message: " . $e->getMessage());
            error_log("ZATCA Error - Response Body: " . $body);

            throw new ZatcaApiException(
                "ZATCA API request failed: {$e->getMessage()}",
                $code,
                $body,
                $e
            );
        }
    }

    /**
     * Validate HTTP status code against success criteria.
     */
    private function isSuccessfulResponse(int $statusCode): bool
    {
        return in_array($statusCode, self::SUCCESS_STATUS_CODES, true) &&
               ($this->allowWarnings || $statusCode === 200);
    }

    /**
     * Parse API response.
     *
     * @param ResponseInterface $response
     * @return array
     * @throws ZatcaApiException If response JSON is invalid.
     */
    private function parseResponse(ResponseInterface $response): array
    {
        $body = (string) $response->getBody();
        $contentType = $response->getHeaderLine('Content-Type');
        
        error_log("ZATCA Parse - Content Type: " . $contentType);
        error_log("ZATCA Parse - Body Length: " . strlen($body));
        
        // Check if response is empty
        if (empty($body)) {
            $msg = sprintf(
                "Empty response received from ZATCA API. Status: %d, Headers: %s",
                $response->getStatusCode(),
                json_encode($response->getHeaders())
            );
            throw new ZatcaApiException($msg);
        }

        // For compliance certificate request, check if it's binary data
        if (strpos($contentType, 'application/json') === false) {
            // Try to extract information from headers
            $secret = $response->getHeaderLine('X-API-Secret');
            $requestId = $response->getHeaderLine('X-Request-ID');
            
            error_log("ZATCA Parse - Found Secret Header: " . ($secret ? 'Yes' : 'No'));
            error_log("ZATCA Parse - Found Request ID Header: " . ($requestId ? 'Yes' : 'No'));

            return [
                'binarySecurityToken' => base64_encode($body),
                'secret' => $secret,
                'requestID' => $requestId
            ];
        }

        // Try to decode JSON
        $data = json_decode($body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new ZatcaApiException(
                sprintf(
                    'Failed to parse JSON response: %s. Response content: %s',
                    json_last_error_msg(),
                    substr($body, 0, 255)
                )
            );
        }

        return $data;
    }

    /**
     * Format certificate string with PEM boundaries.
     *
     * @param string $base64Certificate
     * @return string
     */
    private function formatCertificate(string $base64Certificate): string
    {
        return base64_decode($base64Certificate);
    }

    /**
     * Save certificate data to a JSON file.
     *
     * @param string $certificate The certificate string.
     * @param string $secret      The API secret.
     * @param string $requestId   The request ID.
     * @param string $filePath    Path to save the JSON file.
     * @return void
     * @throws \Exception If failed to encode data to JSON
     * @throws ZatcaStorageException If file cannot be written.
     */
    public function saveToJson(string $certificate, string $secret, string $requestId, string $filePath): void
    {
        $data = [
            'certificate' => $certificate,
            'secret'      => $secret,
            'requestId'   => $requestId,
        ];

        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new \Exception("Failed to encode data to JSON: " . json_last_error_msg());
        }

        (new Storage)->put($filePath, $json);
    }
    
}
