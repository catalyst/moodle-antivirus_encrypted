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

namespace antivirus_encrypted;

use ReflectionClass;
use ReflectionMethod;

/**
 * Tests for antivirus scanner class.
 *
 * @package     antivirus_encrypted
 * @author      Peter Burnett <peterburnett@catalyst-au.net>
 * @copyright   Catalyst IT
 * @license     http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class scanner_test extends \advanced_testcase {

    /** @var string Folder to hold the temporary fixture copied file. */
    private $tempfolder;

    protected function setUp(): void {
        $this->resetAfterTest();

        // Create tempfolder.
        $tempfolder = make_request_directory(false);
        $this->tempfolder = $tempfolder;
    }

    /**
     * Return the path of a copied fixture file.
     *
     * Used to ensure the scanner works on paths where real files would live, outside of the fixture folder.
     * @param string $path
     * @return string
     */
    private function get_file_copy_path(string $path): string {
        // Fixture source path.
        $fullpath = __DIR__ . '/fixtures/' . $path;

        // Copy the file to the tempfolder.
        $newpath = $this->tempfolder . '/' . $path;
        copy($fullpath, $newpath);
        return $newpath;
    }

    /**
     * Data provider for {@see test_scan_file, test_detect_filetype}
     *
     * @return array[]
     */
    public static function file_provider(): array {
        // Each entry is [path, scanresult, filetype, class].
        return [
            ['libreofficedoc-enc.odt', 1, 'libreoffice', 'doc'],
            ['libreofficedoc-nonenc.odt', 0, 'libreoffice', 'doc'],
            ['libreofficepres-enc.odp', 1, 'libreoffice', 'doc'],
            ['libreofficepres-nonenc.odp', 0, 'libreoffice', 'doc'],
            ['libreofficesheet-enc.ods', 1, 'libreoffice', 'doc'],
            ['libreofficesheet-nonenc.ods', 0, 'libreoffice', 'doc'],
            ['zip-enc.zip', 1, 'zip', 'archive'],
            ['zip-nonenc.zip', 0, 'zip', 'archive'],
            ['pdf-enc.pdf', 1, 'pdf', 'doc'],
            ['pdf-nonenc.pdf', 0, 'pdf', 'doc'],
            ['pdf-emptypw.pdf', 0, 'pdf', 'doc'],
            ['notscanned.txt', 0, '', 'other'],
        ];
    }

    /**
     * Test scanning files
     *
     * @dataProvider file_provider
     * @covers \antivirus_encrypted\scanner::scan_file
     * @param mixed $path
     * @param mixed $result
     */
    public function test_scan_file($path, $result) {
        $fullpath = $this->get_file_copy_path($path);
        $scanner = new \antivirus_encrypted\scanner();

        $this->assertEquals($result, $scanner->scan_file($fullpath, $path));
    }

    /**
     * Test scan file mimetype mismatch
     *
     * @covers \antivirus_encrypted\scanner::scan_file
     */
    public function test_scan_file_mimetype_mismatch() {
        $filename = 'mismatchedmimezip.xml';
        $fullpath = $this->get_file_copy_path($filename);
        $scanner = new \antivirus_encrypted\scanner();

        $this->assertEquals(1, $scanner->scan_file($fullpath, $filename));
    }

    /**
     * Test detecting filetypes
     *
     * @dataProvider file_provider
     * @covers \antivirus_encrypted\scanner::detect_filetype
     * @param mixed $path
     * @param mixed $result
     * @param mixed $filetype
     * @param mixed $expectedclassification
     */
    public function test_detect_filetype($path, $result, $filetype, $expectedclassification) {
        $fullpath = $this->get_file_copy_path($path);
        // We need a fresh scanner everytime.
        $scanner = new \antivirus_encrypted\scanner();

        // Let's make stuff public using reflection.
        $reflectedscanner = new ReflectionClass($scanner);
        $reflectedextension = $reflectedscanner->getProperty('extension');
        $reflectedfiletype = $reflectedscanner->getProperty('filetype');
        $reflectedextension->setAccessible(true);
        $reflectedfiletype->setAccessible(true);

        // Now setup the extension.
        $extension = pathinfo($path, PATHINFO_EXTENSION);
        $reflectedextension->setValue($scanner, $extension);

        // Time to do the meaty bit.
        $reflectionmethod = new ReflectionMethod($scanner, 'detect_filetype');
        $reflectionmethod->setAccessible(true);
        $classification = $reflectionmethod->invoke($scanner, $fullpath);

        // Now lets check we get back what we wanted.
        $this->assertEquals($filetype, $reflectedfiletype->getValue($scanner));
        $this->assertEquals($expectedclassification, $classification);
    }

    /**
     * Test detecting filetype mimetype mismatch
     *
     * @covers \antivirus_encrypted\scanner::detect_filetype
     **/
    public function test_detect_filetype_mimetype_mismatch() {
        $filename = 'mismatchedmimezip.xml';
        $fullpath = $this->get_file_copy_path($filename);
        $scanner = new \antivirus_encrypted\scanner();

        // Let's make stuff public using reflection.
        $reflectedscanner = new ReflectionClass($scanner);
        $reflectedextension = $reflectedscanner->getProperty('extension');
        $reflectedfiletype = $reflectedscanner->getProperty('filetype');
        $reflectedextension->setAccessible(true);
        $reflectedfiletype->setAccessible(true);

        // Now setup the extension.
        $extension = pathinfo($filename, PATHINFO_EXTENSION);
        $reflectedextension->setValue($scanner, $extension);

        // Time to do the meaty bit.
        $reflectionmethod = new ReflectionMethod($scanner, 'detect_filetype');
        $reflectionmethod->setAccessible(true);

        // Now we are looking for the classification to be a zip.
        $this->assertEquals('archive', $reflectionmethod->invoke($scanner, $fullpath));
    }
}
