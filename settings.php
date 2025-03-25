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
 * Moodle encrypted scanner API plugin.
 *
 * @package    antivirus_encrypted
 * @copyright  2025 Catalyst IT
 * @author     Matthew Hilton <matthewhilton@catalyst-au.net>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

if (!during_initial_install() && $ADMIN->fulltree) {
    $settings->add(new admin_setting_heading('antivirus_encrypted/pdfbinaries',
        new lang_string('pdfbinaries', 'antivirus_encrypted'),
        new lang_string('pdfbinaries_desc', 'antivirus_encrypted')
    ));

    $settings->add(new admin_setting_configcheckbox('antivirus_encrypted/usegs',
        new lang_string('usegs', 'antivirus_encrypted'),
        new lang_string('usegs_desc', 'antivirus_encrypted'), true));

    $settings->add(new admin_setting_configcheckbox('antivirus_encrypted/useqpdf',
        new lang_string('useqpdf', 'antivirus_encrypted'),
        new lang_string('useqpdf_desc', 'antivirus_encrypted'), false));

    $settings->add(new admin_setting_configexecutable('antivirus_encrypted/pathtoqpdf',
        new lang_string('pathtoqpdf', 'antivirus_encrypted'), '', '/usr/bin/qpdf'));
}
