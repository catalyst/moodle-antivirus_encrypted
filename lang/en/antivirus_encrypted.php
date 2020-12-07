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
 * Strings for component 'antivirus_encrypted', language 'en'.
 *
 * @package     antivirus_encrypted
 * @author      Peter Burnett <peterburnett@catalyst-au.net>
 * @copyright   Catalyst IT
 * @license     http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['pluginname'] = 'Encrypted content';
$string['privacy:metadata'] = 'The antivirus_encrypted plugin stores no user data.';
$string['mimetypemismatch'] = 'File content mimetype did not match registered mimetype for extension.';
$string['encryptedcontentfound'] = 'Encrypted file found. File content was unable to be inspected.';
$string['encryptedcontentmessage'] = '{$a->item} was unable to be inspected, due to encryption on the file. Please upload a non-encrypted file.';
