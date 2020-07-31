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

/**
 * Tests for antivirus scanner class.
 *
 * @package     antivirus_encrypted
 * @author      Peter Burnett <peterburnett@catalyst-au.net>
 * @copyright   Catalyst IT
 * @license     http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_encrypted\tests;

use ReflectionClass;
use ReflectionMethod;

class antivirus_encrypted_scanner_testcase extends \advanced_testcase {

    public static function file_provider() {
        // Each entry is [path, scanresult, filetype, class]
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
            ['notscanned.txt', 0, '', 'other'],
        ];
    }

    /**
     * @dataProvider file_provider
     */
    public function test_scan_file($path, $result) {
        $fullpath = __DIR__ . '/fixtures/' . $path;
        $scanner = new \antivirus_encrypted\scanner();

        $this->assertEquals($result, $scanner->scan_file($fullpath, $path));
    }

    /**
     * @dataProvider file_provider
     */
    public function test_detect_filetype($path, $result, $filetype, $expectedclassification) {
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
        $classification = $reflectionmethod->invoke($scanner);

        // Now lets check we get back what we wanted.
        $this->assertEquals($filetype, $reflectedfiletype->getValue($scanner));
        $this->assertEquals($expectedclassification, $classification);
    }
}