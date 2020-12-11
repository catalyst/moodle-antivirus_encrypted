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

defined('MOODLE_INTERNAL') || die();

/**
 * Scanner class for antivirus_encrypted.
 *
 * @package     antivirus_encrypted
 * @author      Peter Burnett <peterburnett@catalyst-au.net>
 * @copyright   Catalyst IT
 * @license     http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class scanner extends \core\antivirus\scanner {

    const FILE_ARCHIVE = 'archive';
    const FILE_DOCUMENT = 'doc';
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
    public function is_configured() : bool {

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
    public function scan_file($file, $filename) : int {
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

        $enc = false;
        switch ($type) {
            case self::FILE_DOCUMENT:
                $enc = $this->is_document_encrypted($file);
                break;

            case self::FILE_ARCHIVE:
                $enc = $this->is_archive_encrypted($file);
                break;
        }
        if ($enc) {
            $this->set_scanning_notice(get_string('encryptedcontentfound', 'antivirus_encrypted'));
        }
        return $enc ? self::SCAN_RESULT_FOUND : self::SCAN_RESULT_OK;
    }

    /**
     * Checks if provided archive file is encrypted.
     *
     * @param string $file the full path to the file
     * @return boolean whether the file is encrypted
     */
    protected function is_archive_encrypted(string $file) : bool {
        // @codingStandardsIgnoreStart
        // This block will need code eventually.
        if (empty($this->filetype)) {
            // Detect filetype here if not set.
        }
        // @codingStandardsIgnoreEnd

        switch ($this->filetype) {
            case 'zip':
                return $this->is_zip_encrypted($file);
                break;

            default:
                // This file is not a supported archive file.
                return false;
                break;
        }
    }

    /**
     * Checks if provided document file is encrypted.
     *
     * @param string $file the full path to the file
     * @return boolean whether the file is encrypted
     */
    protected function is_document_encrypted(string $file) : bool {
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
                return $this->is_libreoffice_encrypted($file);
                break;

            case 'pdf':
                return $this->is_pdf_encrypted($file);
                break;

            default:
            // This is not a supported document file.
            return false;
            break;
        }
    }

    /**
     * Determines the filetype constant that this file belongs to.
     *
     * @param string $file the full path to the file
     * @return string the file constant
     */
    protected function detect_filetype($file) : string {
        $mimetypes = get_mimetypes_array();
        $type = '';

        $mimetype = mime_content_type($file);
        // Filter array where subarray type is an exact match.
        // If not found, do nothing, we don't care about this file.
        // If found, look for a matching group attached to it.
        // If no group, or group isnt archive or doc, do nothing.
        $matchingexts = array_filter($mimetypes, function($element) use ($mimetype) {
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
     * @return boolean whether the file is encrypted.
     */
    protected function is_zip_encrypted(string $file) : bool {
        // Try to open as a zip. If it fails, may be passworded.
        $zip = zip_open($file);
        if (!is_resource($zip)) {
            return true;
        }

        $data = zip_read($zip);
        if (!$data) {
            // If unable to read data, may be passworded.
            return true;
        }

        return false;
    }

    /**
     * Reads a libreoffice file and determines if it is encrypted.
     *
     * @param string $file the full path to the file
     * @return boolean
     */
    protected function is_libreoffice_encrypted(string $file) : bool {
        // We need to open the archive as a zip and extract the META-INF/manifest.xml and check for encryption data.
        // We have already determined this will open correctly. Any errors should just return true.
        $zip = new \ZipArchive();
        $opened = $zip->open($file);
        if (!$opened) {
            return true;
        }
        $manifest = $zip->getFromName('META-INF/manifest.xml');
        $zip->close();

        // A simple grep for encryption-data string is enough to determine.
        if (!empty($manifest) && stripos($manifest, 'encryption-data')) {
            return true;
        }

        // Making it here means no encryption.
        return false;
    }

    protected function is_pdf_encrypted(string $file) : bool {

        try {
            $pdf = new \assignfeedback_editpdf\pdf();
            $pages = $pdf->setSourceFile($file);
        } catch (\Exception $e) {
            $pdf->_destroy();
            if (stripos($e->getMessage(), 'encrypted')) {
                // There is a good chance this is the encryption message.
                // There are different messages for different FPDI libs.
                return true;
            }
        }
        $pdf->_destroy();
        return false;
    }

    public function get_virus_found_message() {
        return ['string' => 'encryptedcontentmessage', 'component' => 'antivirus_encrypted', 'placeholders' => []];
    }
}
