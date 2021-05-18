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
 * The main jitsi configuration form
 *
 * It uses the standard core Moodle formslib. For more info about them, please
 * visit: http://docs.moodle.org/en/Development:lib/formslib.php
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot.'/course/moodleform_mod.php');

/**
 * Jitsi settings form.
 *
 * @package   mod_jitsi
 * @copyright  2019 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class mod_jitsi_mod_form extends moodleform_mod {

    /**
     * Defines forms elements
     */
    public function definition() {
        global $CFG;
        $mform = $this->_form;
        $mform->addElement('header', 'general', get_string('general', 'form'));
        $mform->addElement('text', 'name', get_string('jitsiname', 'jitsi'), array('size' => '64'));
        if (!empty($CFG->formatstringstriptags)) {
            $mform->setType('name', PARAM_TEXT);
        } else {
            $mform->setType('name', PARAM_CLEANHTML);
        }
        $mform->addRule('name', null, 'required', null, 'client');
        $mform->addRule('name', get_string('maximumchars', '', 255), 'maxlength', 255, 'client');
        $mform->addHelpButton('name', 'modulename', 'jitsi');
        //if ($CFG->jitsi_livebutton == 1) {
        //    $mform->addElement('advcheckbox', 'record', get_string('streamingandrecording', 'jitsi'));
        //}
        $this->standard_intro_elements();

        $mform->addElement('header', 'availability', get_string('availability', 'assign'));
        $mform->setExpanded('availability', true);

        $name = get_string('allow', 'jitsi');
        $options = array('optional' => true);
        $mform->addElement('date_time_selector', 'timeopen', $name, $options);

        $choicesminspre = array(
          5 => 5,
          10 => 10,
          15 => 15,
          20 => 20,
          30 => 30
        );
        $mform->addElement('select', 'minpretime', get_string('minpretime', 'jitsi'), $choicesminspre);
        $mform->disabledIf('minpretime', 'timeopen[enabled]');
        $this->standard_coursemodule_elements();
        $this->add_action_buttons();
    }
}
