<?php

namespace Saleh7\Zatca\Exceptions;

/**
 * Class ZatcaApiException
 *
 * Exception thrown for API communication errors.
 */
class ZatcaApiException extends ZatcaException
{
    public string $responseBody;
    public int $statusCode;
    private array $validationResults;

    public function __construct(string $message, int $statusCode = 0, string $responseBody = '', ?\Throwable $previous = null)
    {
        $this->statusCode = $statusCode;
        $this->responseBody = $responseBody;
        $this->validationResults = $this->parseValidationResults($responseBody);

        // Create a more detailed error message
        $detailedMessage = $this->createDetailedMessage($message);
        
        parent::__construct(
            $detailedMessage,
            [
                'statusCode' => $statusCode,
                'responseBody' => $responseBody,
                'validationResults' => $this->validationResults
            ],
            $statusCode,
            $previous
        );
    }

    private function parseValidationResults(string $responseBody): array
    {
        $data = json_decode($responseBody, true);
        return $data['validationResults'] ?? [];
    }

    private function createDetailedMessage(string $baseMessage): string
    {
        $messages = [];
        $messages[] = $baseMessage;

        if (!empty($this->validationResults)) {
            // Add error messages
            if (!empty($this->validationResults['errorMessages'])) {
                $messages[] = "\nError Messages:";
                foreach ($this->validationResults['errorMessages'] as $error) {
                    $messages[] = sprintf(
                        "- [%s] %s: %s",
                        $error['code'] ?? 'Unknown',
                        $error['category'] ?? 'Unknown',
                        $error['message'] ?? 'No message'
                    );
                }
            }

            // Add warning messages
            if (!empty($this->validationResults['warningMessages'])) {
                $messages[] = "\nWarning Messages:";
                foreach ($this->validationResults['warningMessages'] as $warning) {
                    $messages[] = sprintf(
                        "- [%s] %s: %s",
                        $warning['code'] ?? 'Unknown',
                        $warning['category'] ?? 'Unknown',
                        $warning['message'] ?? 'No message'
                    );
                }
            }

            // Add info messages
            if (!empty($this->validationResults['infoMessages'])) {
                $messages[] = "\nInfo Messages:";
                foreach ($this->validationResults['infoMessages'] as $info) {
                    $messages[] = sprintf(
                        "- [%s] %s: %s",
                        $info['code'] ?? 'Unknown',
                        $info['category'] ?? 'Unknown',
                        $info['message'] ?? 'No message'
                    );
                }
            }

            // Add status if available
            if (isset($this->validationResults['status'])) {
                $messages[] = sprintf("\nValidation Status: %s", $this->validationResults['status']);
            }
        }

        return implode("\n", $messages);
    }

    /**
     * Get the response body from the API call.
     *
     * @return string
     */
    public function getResponseBody(): string
    {
        return $this->responseBody;
    }

    /**
     * Get the HTTP status code from the API call.
     *
     * @return int
     */
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    /**
     * Get the validation results if any.
     *
     * @return array
     */
    public function getValidationResults(): array
    {
        return $this->validationResults;
    }
}
