<?php

namespace antivirus_encrypted;

use coding_exception;

class scan_result {
    const STATUS_DETECTED = 'detected';
    const STATUS_DETECTED_WITH_WARNINGS = 'detected_with_warnings';
    const STATUS_NOT_DETECTED = 'not_detected';
    const STATUS_CANNOT_RUN = 'cannot_run';
    const STATUS_IGNORED = 'ignored'; // TODO

    const STATUSES = [
        self::STATUS_DETECTED,
        self::STATUS_DETECTED_WITH_WARNINGS,
        self::STATUS_NOT_DETECTED,
        self::STATUS_CANNOT_RUN,
        self::STATUS_IGNORED,
    ];

    private string $status;

    private string $message;

    public function __construct(string $status, string $message) {
        if (!in_array($status, self::STATUSES)) {
            throw new coding_exception("Invalid status " . $status);
        }

        $this->status = $status;
        $this->message = $message;
    }

    public static function new(string $status, string $message): scan_result {
        return new scan_result($status, $message);
    }

    public function get_status(): string {
        return $this->status;
    }

    public function get_message(): string {
        return $this->message;
    }
}