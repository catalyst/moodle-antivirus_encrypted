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
     * Returns whether the scanner engine is configured.
     *
     * @return boolean
     */
    public function is_configured() : bool {
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
        // Detect filetype.
        $type = $this->detect_filetype($filename);

        $enc = false;
        switch ($type) {
            case self::FILE_DOCUMENT:
                $enc = $this->is_document_encrypted($file, $filename);
                break;

            case self::FILE_ARCHIVE:
                $enc = $this->is_archive_encrypted($file, $filename);
                break;
        }

        return $enc ? self::SCAN_RESULT_FOUND : self::SCAN_RESULT_OK;
    }

    /**
     * Checks if provided archive file is encrypted.
     *
     * @param string $file the full path to the file
     * @return boolean whether the file is encrypted
     */
    protected function is_archive_encrypted(string $file, string $filename) : bool {
        $extension = pathinfo($filename, PATHINFO_EXTENSION);

        // Zip implementation.
        if ($extension === 'zip') {
            return $this->is_zip_encrypted($file);
        }
    }

    /**
     * Checks if provided document file is encrypted.
     *
     * @param string $file the full path to the file
     * @return boolean whether the file is encrypted
     */
    protected function is_document_encrypted(string $file, string $filename) : bool {

        if (empty($this->filetype)) {
            // We need to figure out the filetype.
        } else {
            $filetype = $this->filetype;
        }

        switch ($filetype) {
            case 'libreoffice':
                return $this->is_libreoffice_encrypted($file);
                break;
        }


        // Use mimetype to determine if libreoffice documents.
        return true;
    }

    /**
     * Determines the filetype constant that this file belongs to.
     *
     * @param string $file the full path to the file
     * @return string the file constant
     */
    protected function detect_filetype(string $filename) : string {

        // Get the file extension
        $extension = pathinfo($filename, PATHINFO_EXTENSION);
        $mimetypes = get_mimetypes_array();
        $type = '';

        if (array_key_exists($extension, $mimetypes)) {
            // Get containing group, and check if document or archive
            $groups = $mimetypes[$extension]['groups'];
            if (!empty($groups)) {
                if (in_array('document', $groups)) {
                    $type = self::FILE_DOCUMENT;
                } else if (in_array('archive', $groups)) {
                    $type = self::FILE_ARCHIVE;
                }
            }

            // If there are no groups, perform more checks to identify type.
            if (stripos($mimetypes[$extension]['type'], 'vnd.oasis.opendocument')) {
                // This is a libreoffice file of some kind. Treat all as docs for scanning purposes.
                $this->filetype = 'libreoffice';
                $type = self::FILE_DOCUMENT;
            }
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
        $zip->open($file);
        $manifest = $zip->getFromName('META-INF/manifest.xml');
        $zip->close();

        // A simple grep for encryption-data string is enough to determine.
        if (!empty($manifest) && !stripos($manifest, 'encryption-data')) {
            return false;
        }

        return true;
    }
}
