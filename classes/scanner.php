<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.
//
/**
 * Scanner implementation for antivirus_encrypted.
 *
 * @package     antivirus_encrypted
 * @author      Peter Burnett <peterburnett@catalyst-au.net>
 * @copyright   Catalyst IT
 * @license     http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace antivirus_encrypted;

use Throwable;
use ZipArchive;

/**
 * Scanner class for antivirus_encrypted.
 *
 * @package     antivirus_encrypted
 * @author      Peter Burnett <peterburnett@catalyst-au.net>
 * @copyright   Catalyst IT
 * @license     http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class scanner extends \core\antivirus\scanner {

    /** @var string */
    const FILE_ARCHIVE = 'archive';

    /** @var string */
    const FILE_DOCUMENT = 'doc';

    /** @var string */
    const FILE_OTHER = 'other';

    /**
     * @var string filetype the filetype for deciding behaviour.
     */
    private $filetype = '';

    /**
     * @var string extension the extension of the file
     */
    private $extension = '';

    /**
     * Returns whether the scanner engine is configured.
     *
     * @return boolean
     */
    public function is_configured(): bool {

        // Check that PHP dependencies are available.
        if (!class_exists('\ZipArchive')) {
            return false;
        }

        return true;
    }

    /**
     * Scan the file
     *
     * @param string $file full path for file.
     * @param string $filename the name of the file.
     * @return int status of the scan
     */
    public function scan_file($file, $filename): int {
        // Check if the file extension is even allowed in the system.
        // If not, return OK and it will be blocked at file level.
        $this->extension = pathinfo($filename, PATHINFO_EXTENSION);
        if (method_exists('\core_filetypes', 'file_apply_siterestrictions')) {
            $filteredtype = \core_filetypes::file_apply_siterestrictions([$this->extension]);
            if (empty($filteredtype)) {
                return self::SCAN_RESULT_OK;
            }
        }

        // Detect type constant, as well as set specific filetype if known (eg libreoffice).
        try {
            $type = $this->detect_filetype($file);
        } catch (\core\antivirus\scanner_exception $e) {
            // File is not what it appears to be. Block it outright.
            $this->set_scanning_notice(get_string('mimetypemismatch', 'antivirus_encrypted'));
            return self::SCAN_RESULT_FOUND;
        }

        // Default not detected.
        $result = scan_result::new(scan_result::STATUS_NOT_DETECTED, '');

        try {
            switch ($type) {
                case self::FILE_DOCUMENT:
                    $result = $this->scan_as_document($file);
                    break;

                case self::FILE_ARCHIVE:
                    $result = $this->scan_as_archive($file);
                    break;
            }
        } catch (Throwable $e) {
            $this->set_scanning_notice('Exception encountered trying to scan file');
            return self::SCAN_RESULT_FOUND;
        }

        // Found something - log and return error.
        if ($result->get_status() == scan_result::STATUS_DETECTED) {
            // TODO do these messages get shown to the user ? If so we might need to sanitize.
            $this->set_scanning_notice(get_string('encryptedcontentfound', 'antivirus_encrypted', $result->get_message()));
            return self::SCAN_RESULT_FOUND;

        }
        if ($result->get_status() == scan_result::STATUS_CANNOT_RUN) {
            // TODO do these messages get shown to the user ? If so we might need to sanitize.
            $this->set_scanning_notice('could not run encrypted scanner, defaulting to block');
            return self::SCAN_RESULT_FOUND;
        }

        // TODO what about scanner cannot run ?

        return self::SCAN_RESULT_OK;
    }

    /**
     * Checks if provided archive file is encrypted.
     *
     * @param string $file the full path to the file
     */
    protected function scan_as_archive(string $file): scan_result {
        switch ($this->filetype) {
            case 'zip':
                return $this->scan_as_zip_archive($file);
                break;

            default:
                // This file is not a supported archive file.
                return scan_result::new(scan_result::STATUS_NOT_DETECTED, '');
                break;
        }
    }

    /**
     * Checks if provided document file is encrypted.
     *
     * @param string $file the full path to the file
     * @return scan_result
     */
    protected function scan_as_document(string $file): scan_result {
        // @codingStandardsIgnoreStart
        // This block will need code eventually.
        if (empty($this->filetype)) {
            // We need to figure out the filetype.
        } else {
            $filetype = $this->filetype;
        }
        // @codingStandardsIgnoreEnd

        switch ($filetype) {
            case 'libreoffice':
                return $this->scan_as_libreoffice_document($file);
                break;

            case 'pdf':
                return $this->scan_as_pdf_document($file);
                break;

            default:
                // This is not a supported document file.
                return scan_result::new(scan_result::STATUS_NOT_DETECTED, 'Unsupported document filetype ' . $filetype);
                break;
        }
    }

    /**
     * Determines the filetype constant that this file belongs to.
     *
     * @param string $file the full path to the file
     * @return string the file constant
     */
    protected function detect_filetype($file): string {
        $mimetypes = get_mimetypes_array();
        $type = '';

        $mimetype = mime_content_type($file);
        // Filter array where subarray type is an exact match.
        // If not found, do nothing, we don't care about this file.
        // If found, look for a matching group attached to it.
        // If no group, or group isnt archive or doc, do nothing.
        $matchingexts = array_filter($mimetypes, function ($element) use ($mimetype) {
            return $element['type'] === $mimetype;
        });

        // If the reported extension matches the mimetype registered extension, use that.
        if (array_key_exists($this->extension, $matchingexts) &&
            array_key_exists('groups', $matchingexts[$this->extension])) {
            $groups = $matchingexts[$this->extension]['groups'];
        } else {
            // Iterate through matches until a group is located.
            foreach ($matchingexts as $ext => $content) {
                if (array_key_exists('groups', $content)) {
                    $groups = $content['groups'];
                    // We aren't trusting the extension that we were given.
                    // Use this matching extension for reference.
                    $this->extension = $ext;
                    break;
                }
            }
        }

        if (!empty($groups)) {
            if (in_array('document', $groups)) {
                $type = self::FILE_DOCUMENT;
                // If properly identified in Document group, set the type to extension.
                $this->filetype = $this->extension;
            } else if (in_array('archive', $groups)) {
                $type = self::FILE_ARCHIVE;
                // If properly identified in Archive group, set the filetype to extension.
                $this->filetype = $this->extension;
            }
        }

        // Now lets do some more intelligent type matching for things that may not have a group.
        if (stripos($mimetype, 'vnd.oasis.opendocument')) {
            // This is a libreoffice file of some kind. Treat all as docs for scanning purposes.
            $this->filetype = 'libreoffice';
            $type = self::FILE_DOCUMENT;
        }

        return empty($type) ? self::FILE_OTHER : $type;
    }

    /**
     * This functions attempts to open and read a zip. Failure points to passworded file.
     * If passed a file that is not a zip this will not be correct.
     *
     * @param string $file the full path to the file.
     */
    protected function scan_as_zip_archive(string $file): scan_result {
        // Try to open as a zip. If it fails, may be passworded.
        $zip = new ZipArchive;
        $status = $zip->open($file);

        if ($status !== true) {
            return scan_result::new(scan_result::STATUS_DETECTED, 'Unable to open zip, assuming encrypted');
        }

        $data = $zip->statIndex(0);
        if ($data === false) {
            // If unable to read data, may be passworded.
            return scan_result::new(scan_result::STATUS_DETECTED, 'Unable to read zip data, assuming encrypted');
        }

        // Finally, check for an encryption method on the file.
        if (array_key_exists('encryption_method', $data) && $data['encryption_method'] !== ZipArchive::EM_NONE) {
            return scan_result::new(scan_result::STATUS_DETECTED, 'Zip archive encryption method enabled');
        }

        return scan_result::new(scan_result::STATUS_NOT_DETECTED,  '');
    }

    /**
     * Reads a libreoffice file and determines if it is encrypted.
     *
     * @param string $file the full path to the file
     */
    protected function scan_as_libreoffice_document(string $file): scan_result {
        // We need to open the archive as a zip and extract the META-INF/manifest.xml and check for encryption data.
        // We have already determined this will open correctly. Any errors should just return true.
        $zip = new \ZipArchive();
        $opened = $zip->open($file);
        if (!$opened) {
            return new scan_result(scan_result::STATUS_DETECTED, 'Unable to open libreoffice file, assuming encrypted');
        }
        $manifest = $zip->getFromName('META-INF/manifest.xml');
        $zip->close();

        // A simple grep for encryption-data string is enough to determine.
        if (!empty($manifest) && stripos($manifest, 'encryption-data')) {
            return new scan_result(scan_result::STATUS_DETECTED, 'Encryption data found in manifest of libreoffice file');
        }

        // Making it here means no encryption.
        return new scan_result(scan_result::STATUS_NOT_DETECTED, '');
    }

    protected function scan_as_pdf_document(string $file): scan_result {
        // Run both Ghostscript and PDFInfo.
        $gsresult = $this->scan_as_pdf_with_ghostscript($file);
        $pdfinforesult = $this->scan_as_pdf_with_pdfinfo($file);

        // First we rely on ghostscript, but only if no warnings are detected.
        if ($gsresult->get_status() == scan_result::STATUS_DETECTED)  {
            return $gsresult;
        // Second, if pdfinfo couldn't run (e.g. not installed), and ghostscript detected but with warnings, then just return the gs result.
        } else if ($gsresult->get_status() == scan_result::STATUS_DETECTED_WITH_WARNINGS && $pdfinforesult->get_status() == scan_result::STATUS_CANNOT_RUN) {
            return $gsresult;
        // Third, if pdfinfo could run and detected, and ghostscript detected with warnings, return true (likely just a malformed pdf that ghostscript doesn't like).
        } else if ($gsresult->get_status() == scan_result::STATUS_DETECTED_WITH_WARNINGS && $pdfinforesult->get_status() == scan_result::STATUS_DETECTED) {
            return scan_result::new(scan_result::STATUS_DETECTED, 'Ghostscript detected but with warnings: ' . $gsresult->get_message() . ' but pdfinfo also detected: ' . $pdfinforesult->get_message() . ' - highly likely encrypted');
        }

        return scan_result::new(scan_result::STATUS_NOT_DETECTED, '');
    }

    /**
     * Returns whether or not the PDF is encrypted using ghostscript
     *
     * @param string $file the full path to the file
     * @return scan_result
     */
    protected function scan_as_pdf_with_ghostscript(string $file): scan_result {
        global $CFG;

        // Check if gs binary exists.
        if (!is_executable($CFG->pathtogs)) {
            return scan_result::new(scan_result::STATUS_CANNOT_RUN, 'Ghostscript binary not found');
        }

        // Run file through ghostscript to ensure no encrpytion.
        // If no path set, try the regular path. If it fails, The doc should pass.
        $gsexec = \escapeshellarg($CFG->pathtogs);
        $path = \escapeshellarg($file);
        $devnull = \escapeshellarg('/dev/null');
        $command = "$gsexec -sDEVICE=pdfwrite -dFirstPage=1 -dLastPage=1 -dBATCH -dNOPAUSE -sOutputFile=$devnull $path";

        // Exec the GS run, then check for a pw error.
        exec("$command 2>&1", $output);
        $passworddetected = stripos(implode(',', $output), 'This file requires a password for access.') !== false;
        $warningdetected = stripos(implode(',', $output), 'Invalid /Length supplied in Encryption dictionary.') !== false;

        if ($passworddetected && !$warningdetected) {
            return scan_result::new(scan_result::STATUS_DETECTED, '');
        } else if ($passworddetected && $warningdetected) {
            return scan_result::new(scan_result::STATUS_DETECTED_WITH_WARNINGS, 'Invalid encryption dictionary warning detected, likely not compliant PDF');
        } else {
            return scan_result::new(scan_result::STATUS_NOT_DETECTED, '');
        }
    }

    /**
     * Returns whether or not a PDF is encrypted using pdfinfo
     *
     * @param string $file the full path to the file
     * @return scan_result
     */
    protected function scan_as_pdf_with_pdfinfo(string $file): scan_result {
        $pdfinfopath = get_config('antivirus_encrypted', 'pathtopdfinfo'); // TODO do we need a gui setting

        // Ensure PDFinfo exists.
        if (!is_executable($pdfinfopath)) {
            return scan_result::new(scan_result::STATUS_CANNOT_RUN, 'Pdfinfo binary not found');
        }

        $pdfinfoexec = \escapeshellarg($pdfinfopath);
        $path = \escapeshellarg($file);
        $command = "$pdfinfoexec $path";

        exec("$command 2>&1", $output);
        if (stripos(implode(',', $output), 'Incorrect password') !== false) {
            return scan_result::new(scan_result::STATUS_DETECTED, 'Password detected by PDFInfo');
        }

        return scan_result::new(scan_result::STATUS_NOT_DETECTED, '');
    }

    /**
     * Returns the virus found message structure.
     *
     * @return array
     */
    public function get_virus_found_message() {
        return ['string' => 'encryptedcontentmessage', 'component' => 'antivirus_encrypted', 'placeholders' => []];
    }
}
