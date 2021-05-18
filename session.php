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
 * Prints a particular instance of jitsi
 *
 * You can have a rather longer description of the file as well,
 * if you like, and it can span multiple lines.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname(dirname(dirname(__FILE__))).'/config.php');
require_once(dirname(dirname(dirname(__FILE__))).'/lib/moodlelib.php');
require_once(dirname(__FILE__).'/lib.php');

$PAGE->set_url($CFG->wwwroot.'/mod/jitsi/session.php');

$state = optional_param('state', null, PARAM_TEXT);

// Si no hay state es una conexión normal que no va a tener grabación.
if ($state == null) {
    $courseid = required_param('courseid', PARAM_INT);
    $cmid = required_param('cmid', PARAM_INT);
    $nombre = required_param('nom', PARAM_TEXT);
    $session = required_param('ses', PARAM_TEXT);
    $avatar = $CFG->jitsi_showavatars == true ? required_param('avatar', PARAM_TEXT) : null;
    $teacher = required_param('t', PARAM_BOOL);

    // Hay grabación.
} else {
    $paramdecode = base64urldecode($state);
    $parametrosarray = explode("&", $paramdecode);
    $avatararray = $parametrosarray[0];
    $nomarray = $parametrosarray[1];
    $sessionarray = $parametrosarray[2];
    $coursearray = $parametrosarray[3];
    $cmidarray = $parametrosarray[4];
    $tarray = $parametrosarray[5];
    $statesesarray = $parametrosarray[6];
    $avatara = explode("=", $avatararray);
    $nombrea = explode("=", $nomarray);
    $sessiona = explode("=", $sessionarray);
    $courseida = explode("=", $coursearray);
    $cmida = explode("=", $cmidarray);
    $teachera = explode("=", $tarray);
    $statesesa = explode("=", $statesesarray);
    $avatar = $avatara[1];
    $nombre = $nombrea[1];
    $session = $sessiona[1];
    $courseid = $courseida[1];
    $cmid = $cmida[1];
    $teacher = $teachera[1];
    $stateses = $statesesa[1];
}
$sessionnorm = str_replace(array(' ', ':', '"'), '', $session);
require_login($courseid);

$PAGE->set_title($session);
$PAGE->set_heading($session);
echo $OUTPUT->header();
$module = $DB->get_record('modules', array('name' => 'jitsi'));

$jitsimodule = $DB->get_record('course_modules', array('module' => $module->id, 'id' => $cmid));
$jitsi = $DB->get_record('jitsi', array('id' => $jitsimodule->instance));
// Grabaciones.
if ($CFG->jitsi_livebutton == 1 && has_capability('mod/jitsi:record', $PAGE->context) &&
    $jitsi->record == 1 && ($jitsi->recording == '' || $jitsi->recording == 'stop')) {
    // Api google.
    if (!file_exists(__DIR__ . '/api/vendor/autoload.php')) {
        throw new \Exception('please run "composer require google/apiclient:~2.0" in "' . __DIR__ .'"');
    }
    require_once(__DIR__ . '/api/vendor/autoload.php');

    /*
    * You can acquire an OAuth 2.0 client ID and client secret from the
    * {{ Google Cloud Console }} <{{ https://cloud.google.com/console }}>
    * For more information about using OAuth 2.0 to access Google APIs, please see:
    * <https://developers.google.com/youtube/v3/guides/authentication>
    * Please ensure that you have enabled the YouTube Data API for your project.
    */
    $oauth2clientid = $CFG->jitsi_oauth_id;

    $oauth2clientsecret = $CFG->jitsi_oauth_secret;

    $client = new Google_Client();
    $client->setClientId($oauth2clientid);
    $client->setClientSecret($oauth2clientsecret);
    $client->setScopes('https://www.googleapis.com/auth/youtube');
    $redirect = filter_var('http://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'], FILTER_SANITIZE_URL);
    $client->setRedirectUri($redirect);

    // Define an object that will be used to make all API requests.
    $youtube = new Google_Service_YouTube($client);

    // Check if an auth token exists for the required scopes.
    $tokensessionkey = 'token-' . $client->prepareScopes();
    if (isset($_GET['code'])) {
        if (strval($_SESSION['stateses']) !== strval($stateses)) {
            die('The session state did not match.');
        }
        $client->authenticate($_GET['code']);
        $_SESSION[$tokensessionkey] = $client->getAccessToken();
    }

    if (isset($_SESSION[$tokensessionkey])) {
        $client->setAccessToken($_SESSION[$tokensessionkey]);
    }

    // Check to ensure that the access token was successfully acquired.
    if ($client->getAccessToken()) {
        try {
            $records = $DB->get_records('jitsi_record', array('jitsi' => $jitsi->id));
            if (onstreaming($jitsi, $records) == false) {
                $respuestas = generatenewvideo($session, $youtube);
                $streamsresponse = $respuestas[0];
                $broadcastsresponse = $respuestas[1];
            }
        } catch (Google_Service_Exception $e) {
            // If the user hasn't authorized the app, initiate the OAuth flow.
            $stateses = mt_rand();
            $_SESSION['stateses'] = $stateses;
            $urlprams = "avatar=".$avatar."&nom=".$nombre."&ses=".$session."&courseid="
                .$courseid."&cmid=".$cmid."&t=".$teacher."&stateses=".$stateses;
            $state = base64urlencode($urlprams);
            $client->setState($state);

            $authurl = $client->createAuthUrl();
            echo "<p>Youu need to <a href=".$authurl.">authorize access</a> before proceeding.<p>";
        } catch (Google_Exception $e) {
            echo "excepcion".$e->getMessage();
        }
        $_SESSION[$tokensessionkey] = $client->getAccessToken();
        // Parte de jitsi.
        if ($teacher == 1) {
            $teacher = true;
            $affiliation = "owner";
        } else {
            $teacher = false;
            $affiliation = "member";
        }
        $context = context_module::instance($cmid);
        if (!has_capability('mod/jitsi:view', $context)) {
            notice(get_string('noviewpermission', 'jitsi'));
        }
        $jitsimodule = $DB->get_record('modules', array('name' => 'jitsi'));
        $jitsi = $DB->get_record('course_modules', array('module' => $jitsimodule->id, 'id' => $cmid));
        $header = json_encode([
            "kid" => "jitsi/custom_key_name",
            "typ" => "JWT",
            "alg" => "HS256"
        ], JSON_UNESCAPED_SLASHES);
        $base64urlheader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $payload  = json_encode([
            "context" => [
                "user" => [
                    "affiliation" => $affiliation,
                    "avatar" => $avatar,
                    "name" => $nombre,
                    "email" => "",
                    "id" => ""
                ],
                "group" => ""
            ],
            "aud" => "jitsi",
            "iss" => $CFG->jitsi_app_id,
            "sub" => $CFG->jitsi_domain,
            "room" => urlencode($sessionnorm),
            "exp" => time() + 24 * 3600,
            "moderator" => $teacher
        ], JSON_UNESCAPED_SLASHES);
        $base64urlpayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        $secret = $CFG->jitsi_secret;
        $signature = hash_hmac('sha256', $base64urlheader . "." . $base64urlpayload, $secret, true);
        $base64urlsignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
        $jwt = $base64urlheader . "." . $base64urlpayload . "." . $base64urlsignature;
        echo "<script src=\"//ajax.googleapis.com/ajax/libs/jquery/2.0.0/jquery.min.js\"></script>";
        echo "<script src=\"https://".$CFG->jitsi_domain."/external_api.js\"></script>\n";
        $streamingoption = '';
        $desktop = '';
        if (has_capability('mod/jitsi:sharedesktop', $context)) {
            $desktop = 'desktop';
        }
        $youtubeoption = '';
        if ($CFG->jitsi_shareyoutube == 1) {
            $youtubeoption = 'sharedvideo';
        }
        $bluroption = '';
        if ($CFG->jitsi_blurbutton == 1) {
            $bluroption = 'videobackgroundblur';
        }
        $security = '';
        if ($CFG->jitsi_securitybutton == 1) {
            $security = 'security';
        }
        $invite = '';
        if ($CFG->jitsi_invitebuttons == 1) {
            $invite = 'invite';
        }
        $buttons = "['microphone', 'camera', 'closedcaptions', '".$desktop."', 'fullscreen',
            'fodeviceselection', 'hangup', 'chat', 'recording', 'etherpad', '".$youtubeoption."',
            'settings', 'raisehand', 'videoquality', 'filmstrip', '".$invite."', 'stats',
            'shortcuts', 'tileview', '".$bluroption."', 'download', 'help', 'mute-everyone',
            'mute-video-everyone', '".$security."']";

        echo "<script>\n";
        echo "const domain = \"".$CFG->jitsi_domain."\";\n";
        echo "const options = {\n";
	echo "configOverwrite: {\n";
	echo "disableDeepLinking: true,\n";
        echo "toolbarButtons: ".$buttons.",\n";
        echo "disableProfile: true,\n";
        echo "prejoinPageEnabled: false,";
        echo "channelLastN: ".$CFG->jitsi_channellastcam.",\n";
        echo "startWithAudioMuted: true,\n";
        echo "startWithVideoMuted: true,\n";
        echo "},\n";
        echo "roomName: \"".urlencode($sessionnorm)."\",\n";
        if ($CFG->jitsi_app_id != null && $CFG->jitsi_secret != null) {
            echo "jwt: \"".$jwt."\",\n";
        }
        if ($CFG->branch < 36) {
            if ($CFG->theme == 'boost' || in_array('boost', $themeconfig->parents)) {
                echo "parentNode: document.querySelector('#region-main .card-body'),\n";
            } else {
                echo "parentNode: document.querySelector('#region-main'),\n";
            }
        } else {
            echo "parentNode: document.querySelector('#region-main'),\n";
        }
        echo "interfaceConfigOverwrite:{\n";
        echo "TOOLBAR_BUTTONS: ".$buttons.",\n";
        echo "SHOW_JITSI_WATERMARK: true,\n";
        echo "JITSI_WATERMARK_LINK: '".$CFG->jitsi_watermarklink."',\n";
        echo "},\n";
        echo "width: '100%',\n";
        echo "height: 650,\n";
        echo "}\n";
        echo "const api = new JitsiMeetExternalAPI(domain, options);\n";
        echo "api.executeCommand('displayName', '".$nombre."');\n";
        echo "api.executeCommand('avatarUrl', '".$avatar."');\n";
        if ($CFG->jitsi_finishandreturn == 1) {
            echo "api.on('readyToClose', () => {\n";
            echo "    api.dispose();\n";
            echo "    location.href=\"".$CFG->wwwroot."/mod/jitsi/view.php?id=".$cmid."\";";
            echo  "});\n";
        }
        if ($CFG->jitsi_password != null) {
            echo "api.addEventListener('participantRoleChanged', function(event) {";
            echo "    if (event.role === \"moderator\") {";
            echo "        api.executeCommand('password', '".$CFG->jitsi_password."');";
            echo "    }";
            echo "});";
            echo "api.on('passwordRequired', function ()";
            echo "{";
            echo "    api.executeCommand('password', '".$CFG->jitsi_password."');";
            echo "});";
        }

        echo "api.addEventListener('recordingStatusChanged', function(event) {";
        // Dudo si ponerlo.
        echo "    if (event['on']){";
        echo "        document.getElementById(\"startstream\").disabled = true;";
        echo "        document.getElementById(\"stopstream\").disabled = false;";
        echo "    } else if (!event['on']){";
        echo "        document.getElementById(\"stopstream\").disabled = true;";
        echo "        document.getElementById(\"startstream\").disabled = true;";
        // Fin dudo si ponerlo.
        echo "    }";
        echo "    require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {";
        echo "        ajax.call([{";
        echo "            methodname: 'mod_jitsi_state_record',";
        echo "            args: {jitsi:".$jitsi->instance.", state: event['on']},";
        echo "            done: console.log(\"Cambio grabación\"),";
        echo "            fail: notification.exception";
        echo "        }]);";
        echo "        console.log(event['on']);";
        echo "    })";
        echo "});";

        echo "function stream(){";
        echo "document.getElementById(\"startstream\").disabled = true;";
        echo "document.getElementById(\"stopstream\").disabled = false;";
        echo "api.executeCommand('startRecording', {";
        echo "    mode: 'stream',";
        echo "    youtubeStreamKey: '".$streamsresponse['cdn']['ingestionInfo']['streamName']."' "; // The youtube stream key.
        echo "});";
        echo "}";

        echo "function stopStream(){";
        echo "document.getElementById(\"startstream\").disabled = false;";
        echo "document.getElementById(\"stopstream\").disabled = true;";
        echo "api.executeCommand('stopRecording', 'stream');";
        echo "}";
        echo "</script>\n";

        echo "<div class=\"row\">";
        echo "<div class=\"col-sm\">";
        echo "<button onclick=\"stream()\" type=\"button\" class=\"btn btn-secondary\" id=\"startstream\">Start Stream</button>";
        echo "";
        echo "<button onclick=\"stopStream()\" type=\"button\" class=\"btn btn-secondary\"
              id=\"stopstream\" disabled=\"true\">Stop Stream</button>";
        echo "</div>";
        echo " <div class=\"col-sm\">";
        echo "<span class=\"align-middle text-right\"><p class=\"lead\">https://youtu.be/".$broadcastsresponse['id']."</p></span>";
        echo "</div>";
        echo "</div>";

        $record = new stdClass();
        $record->jitsi = $jitsi->id;
        $record->link = $broadcastsresponse['id'];

        $jitsiob = $DB->get_record('jitsi', array('id' => $jitsi->instance));
        $jitsiob->recording = 'pre';

        $DB->insert_record('jitsi_record', $record);
        $DB->update_record('jitsi', $jitsiob);
        echo "<hr>";

        // Fin copia de abajo.
    } else {
        // If the user hasn't authorized the app, initiate the OAuth flow.
        $stateses = mt_rand();
        $_SESSION['stateses'] = $stateses;
        $urlprams = "avatar=".$avatar."&nom=".$nombre."&ses=".$session."&courseid=".$courseid.
            "&cmid=".$cmid."&t=".$teacher."&stateses=".$stateses;
        $state = base64urlencode($urlprams);
        $client->setState($state);
        $authurl = $client->createAuthUrl();
        echo "<p>You need to <a href=".$authurl.">authorize access</a> before proceeding.<p>";
    }
    // Fin api google.
    // Grabaciones no.
} else {
    if ($teacher == 1) {
        $teacher = true;
        $affiliation = "owner";
    } else {
        $teacher = false;
        $affiliation = "member";
    }
    $context = context_module::instance($cmid);
    if (!has_capability('mod/jitsi:view', $context)) {
        notice(get_string('noviewpermission', 'jitsi'));
    }
    $desktop = '';
    if (has_capability('mod/jitsi:sharedesktop', $context)) {
        $desktop = 'desktop';
    }
    $youtubeoption = '';
    if ($CFG->jitsi_shareyoutube == 1) {
        $youtubeoption = 'sharedvideo';
    }
    $bluroption = '';
    if ($CFG->jitsi_blurbutton == 1) {
        $bluroption = 'select-background';
    }
    $security = '';
    if ($CFG->jitsi_securitybutton == 1) {
        $security = 'security';
    }
    $invite = '';
    if ($CFG->jitsi_invitebuttons == 1) {
        $invite = 'invite';
    }
    $buttons = "['microphone', 'camera', 'closedcaptions', '".$desktop."', 'fullscreen', 'fodeviceselection',
        'hangup', 'chat', 'recording', 'etherpad', '".$youtubeoption."', 'settings', 'raisehand', 'videoquality',
        'filmstrip', '".$invite."', 'stats', 'shortcuts', 'tileview', '".$bluroption."', 'download', 'help',
        'mute-everyone', 'mute-video-everyone', '".$security."']";
    $jitsimodule = $DB->get_record('modules', array('name' => 'jitsi'));

    $jitsi = $DB->get_record('course_modules', array('module' => $jitsimodule->id, 'id' => $cmid));
    $header = json_encode([
        "kid" => "jitsi/custom_key_name",
        "typ" => "JWT",
        "alg" => "HS256"
    ], JSON_UNESCAPED_SLASHES);
    $base64urlheader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $payload  = json_encode([
        "context" => [
            "user" => [
                "affiliation" => $affiliation,
                "avatar" => $avatar,
                "name" => $nombre,
                "email" => "",
                "id" => ""
            ],
            "group" => ""
        ],
        "aud" => "jitsi",
        "iss" => $CFG->jitsi_app_id,
        "sub" => $CFG->jitsi_domain,
        "room" => urlencode($sessionnorm),
        "exp" => time() + 24 * 3600,
        "moderator" => $teacher
    ], JSON_UNESCAPED_SLASHES);
    $base64urlpayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
    $secret = $CFG->jitsi_secret;
    $signature = hash_hmac('sha256', $base64urlheader . "." . $base64urlpayload, $secret, true);
    $base64urlsignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
    $jwt = $base64urlheader . "." . $base64urlpayload . "." . $base64urlsignature;
    echo "<script src=\"//ajax.googleapis.com/ajax/libs/jquery/2.0.0/jquery.min.js\"></script>";
    echo "<script src=\"https://".$CFG->jitsi_domain."/external_api.js\"></script>\n";
    echo "<script>\n";
    echo "const domain = \"".$CFG->jitsi_domain."\";\n";
    echo "const options = {\n";
    echo "configOverwrite: {\n";
    echo "disableDeepLinking: true,\n";
    echo "enableClosePage: true,\n";

    echo "disableProfile: true,\n";
    echo "toolbarButtons: ".$buttons.",\n";
    echo "prejoinPageEnabled: false,";
    echo "channelLastN: ".$CFG->jitsi_channellastcam.",\n";
    echo "startWithAudioMuted: true,\n";
    echo "startWithVideoMuted: true,\n";
    echo "},\n";
    echo "roomName: \"".urlencode($sessionnorm)."\",\n";
    if ($CFG->jitsi_app_id != null && $CFG->jitsi_secret != null) {
        echo "jwt: \"".$jwt."\",\n";
    }
    if ($CFG->branch < 36) {
        if ($CFG->theme == 'boost' || in_array('boost', $themeconfig->parents)) {
            echo "parentNode: document.querySelector('#region-main .card-body'),\n";
        } else {
            echo "parentNode: document.querySelector('#region-main'),\n";
        }
    } else {
        echo "parentNode: document.querySelector('#region-main'),\n";
    }

    $desktop = '';
    if (has_capability('mod/jitsi:sharedesktop', $context)) {
        $desktop = 'desktop';
    }
    $youtubeoption = '';
    if ($CFG->jitsi_shareyoutube == 1) {
        $youtubeoption = 'sharedvideo';
    }
    $bluroption = '';
    if ($CFG->jitsi_blurbutton == 1) {
        $bluroption = 'select-background';
    }
    $security = '';
    if ($CFG->jitsi_securitybutton == 1) {
        $security = 'security';
    }
    $invite = '';
    if ($CFG->jitsi_invitebuttons == 1) {
        $invite = 'invite';
    }

    echo "interfaceConfigOverwrite:{\n";
    echo "TOOLBAR_BUTTONS: ".$buttons.",\n";
    echo "SHOW_JITSI_WATERMARK: true,\n";
    echo "JITSI_WATERMARK_LINK: '".$CFG->jitsi_watermarklink."',\n";
    echo "},\n";
    echo "width: '100%',\n";
    echo "height: 650,\n";
    echo "}\n";
    echo "const api = new JitsiMeetExternalAPI(domain, options);\n";
    echo "api.executeCommand('displayName', '".$nombre."');\n";
    echo "api.executeCommand('avatarUrl', '".$avatar."');\n";
    if ($CFG->jitsi_finishandreturn == 1) {
        echo "api.on('readyToClose', () => {\n";
        echo      "api.dispose();\n";
        echo      "location.href=\"".$CFG->wwwroot."/mod/jitsi/view.php?id=".$cmid."\";";
        echo  "});\n";
    }
    if ($CFG->jitsi_password != null) {
        echo "api.addEventListener('participantRoleChanged', function(event) {";
        echo "    if (event.role === \"moderator\") {";
        echo "        api.executeCommand('password', '".$CFG->jitsi_password."');";
        echo "    }";
        echo "});";
        echo "api.on('passwordRequired', function ()";
        echo "{";
        echo "    api.executeCommand('password', '".$CFG->jitsi_password."');";
        echo "});";
    }

    echo "function stopStream(){";
    echo "  api.executeCommand('stopRecording', 'stream');";
    echo "}";

    echo "</script>\n";
}

echo $OUTPUT->footer();

function base64urlencode($inputstr) {
    return strtr(base64_encode($inputstr), '+/=', '-_,');
}

function base64urldecode($inputstr) {
    return base64_decode(strtr($inputstr, '-_,', '+/='));
}

function generatenewvideo($session, $youtube) {
    // Create an object for the liveBroadcast resource's snippet. Specify values.
    // for the snippet's title, scheduled start time, and scheduled end time.
    $broadcastsnippet = new Google_Service_YouTube_LiveBroadcastSnippet();
    $testdate = time();
    $broadcastsnippet->setTitle($session." (".date('Y-m-d\TH:i:s', $testdate).")");
    $broadcastsnippet->setScheduledStartTime(date('Y-m-d\TH:i:s', $testdate));

    // Create an object for the liveBroadcast resource's status, and set the.
    // broadcast's status to "private".
    $status = new Google_Service_YouTube_LiveBroadcastStatus();
    $status->setPrivacyStatus('unlisted');
    $status->setSelfDeclaredMadeForKids('true');
    $contentdetails = new Google_Service_YouTube_LiveBroadcastContentDetails();
    $contentdetails->setEnableAutoStart(true);
    $contentdetails->setEnableAutoStop(true);
    $contentdetails->setEnableEmbed(true);
    // Create the API request that inserts the liveBroadcast resource.
    $broadcastinsert = new Google_Service_YouTube_LiveBroadcast();
    $broadcastinsert->setSnippet($broadcastsnippet);
    $broadcastinsert->setStatus($status);
    $broadcastinsert->setKind('youtube#liveBroadcast');
    $broadcastinsert->setContentDetails($contentdetails);
    // Execute the request and return an object that contains information.
    // about the new broadcast.
    $broadcastsresponse = $youtube->liveBroadcasts->insert('snippet,status,contentDetails', $broadcastinsert, array());
    // Create an object for the liveStream resource's snippet. Specify a value.
    // for the snippet's title.
    $streamsnippet = new Google_Service_YouTube_LiveStreamSnippet();
    $streamsnippet->setTitle('New Stream');
    // Create an object for content distribution network details for the live.
    // stream and specify the stream's format and ingestion type.
    $cdn = new Google_Service_YouTube_CdnSettings();
    $cdn->setIngestionType('rtmp');
    $cdn->setResolution("variable");
    $cdn->setFrameRate("variable");
    // Create the API request that inserts the liveStream resource.
    $streaminsert = new Google_Service_YouTube_LiveStream();
    $streaminsert->setSnippet($streamsnippet);
    $streaminsert->setCdn($cdn);
    $streaminsert->setKind('youtube#liveStream');
    // Execute the request and return an object that contains information.
    // about the new stream.

    $streamsresponse = $youtube->liveStreams->insert('snippet,cdn', $streaminsert, array());
    // Bind the broadcast to the live stream.

    $bindbroadcastresponse = $youtube->liveBroadcasts->bind($broadcastsresponse['id'], 'id,contentDetails',
        array('streamId' => $streamsresponse['id'], ));
    return [$streamsresponse, $broadcastsresponse];
}

function onstreaming($jitsi, $records) {
    $res = false;
    foreach ($records as $record) {
        if ($record->link == $jitsi->recording) {
            $res = true;
        }
    }
    // La idea es mirar todos los records a ver si coinciden, si coincide alguna es que esta emitiendo.
    return $res;
}
