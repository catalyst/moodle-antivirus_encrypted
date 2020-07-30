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

class antivirus_encrypted_scanner_testcase extends \advanced_testcase {

    public static function scan_file_provider() {
        // Each entry is [path, result]
        return [
            ['libreofficedoc-enc.odt', 1],
            ['libreofficedoc-nonenc.odt', 0],
            ['libreofficepres-enc.odp', 1],
            ['libreofficepres-nonenc.odp', 0],
            ['libreofficesheet-enc.ods', 1],
            ['libreofficesheet-nonenc.ods', 0],
            ['zip-enc.zip', 1],
            ['zip-nonenc.zip', 0],
            ['pdf-enc.pdf', 1],
            ['pdf-nonenc.pdf', 0],
        ];
    }

    /**
     * @dataProvider scan_file_provider
     */
    public function test_scan_file($path, $expected) {
        $fullpath = __DIR__ . '/fixtures/' . $path;
        $scanner = new \antivirus_encrypted\scanner();

        $this->assertEquals($expected, $scanner->scan_file($fullpath, $path));
    }
}