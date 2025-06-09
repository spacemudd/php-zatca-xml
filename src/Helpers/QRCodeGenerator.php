<?php

namespace Saleh7\Zatca\Helpers;

use InvalidArgumentException;
use Saleh7\Zatca\Tag;
use Saleh7\Zatca\Tags\CertificateSignature;
class QRCodeGenerator
{
    /**
     * @var Tag[] Array of Tag instances.
     */
    protected array $tags = [];

    /**
     * @var bool Whether this is for a simplified invoice
     */
    protected bool $isSimplified = false;

    /**
     * Private constructor.
     *
     * Filters the input to include only valid Tag instances.
     *
     * @param Tag[] $tags Array of Tag objects.
     * @param bool $isSimplified Whether this is for a simplified invoice
     *
     * @throws InvalidArgumentException if no valid Tag instances are provided.
     */
    private function __construct(array $tags, bool $isSimplified = false)
    {
        $this->isSimplified = $isSimplified;
        
        $this->tags = array_filter($tags, function ($tag) {
            return $tag instanceof Tag;
        });

        if (count($this->tags) === 0) {
            throw new InvalidArgumentException('Malformed data structure: no valid Tag instances found.');
        }
        
        // Reorder tags for simplified invoices to ensure certificate signature is in correct position
        if ($this->isSimplified) {
            $this->reorderTagsForSimplifiedInvoice();
        }
    }

    /**
     * Reorders tags for simplified invoices to ensure correct ordering
     * For simplified invoices, certificate signature must come after the base tags (1-5)
     * but before the hash and digital signature tags (6-7)
     */
    private function reorderTagsForSimplifiedInvoice(): void
    {
        $baseTags = [];
        $certificateSignature = null;
        $otherTags = [];
        
        foreach ($this->tags as $tag) {
            if ($tag instanceof CertificateSignature || $tag->getTag() === 9) {
                $certificateSignature = $tag;
            } elseif ($tag->getTag() >= 1 && $tag->getTag() <= 5) {
                $baseTags[] = $tag;
            } else {
                $otherTags[] = $tag;
            }
        }
        
        $orderedTags = array_merge($baseTags, $certificateSignature ? [$certificateSignature] : [], $otherTags);
        $this->tags = $orderedTags;
    }

    /**
     * Encodes the TLV string into Base64.
     *
     * @return string Base64 encoded TLV string.
     */
    public function encodeBase64(): string
    {
        return base64_encode($this->encodeTLV());
    }

    /**
     * Create a QRCodeGenerator instance from an array of Tag objects.
     *
     * @param Tag[] $tags Array of Tag objects.
     * @param bool $isSimplified Whether this is for a simplified invoice
     *
     * @return QRCodeGenerator
     */
    public static function createFromTags(array $tags, bool $isSimplified = false): QRCodeGenerator
    {
        return new self($tags, $isSimplified);
    }

    /**
     * Encodes the tags into a TLV (Tag-Length-Value) formatted string.
     *
     * @return string TLV encoded string.
     */
    public function encodeTLV(): string
    {
        return implode('', array_map(function (Tag $tag) {
            return (string) $tag;
        }, $this->tags));
    }
}
