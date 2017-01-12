<?php
/* Script for searching of viruses.
 * AUTHOR: Allmektiger <allmektiger@gmail.com>
 * DISTRIBUTED UNDER GNU GPL 2.0*/

$mask = array("php"); // array of masks or NULL
$ignore = NULL; // array of ignoring directories or NULL
$period = 86400 * 999;
$start_folder = "/path/to/site/root";

function scan_tree ($folder, $period, $mask=NULL, $ignore = NULL) {
	$files = scandir ($folder);
	foreach ($files as $file) {
		if (($file == '.') || ($file == '..') || (is_array ($ignore) && in_array ($file, $ignore))) continue;
		$item = $folder.DIRECTORY_SEPARATOR.$file;
		if (is_dir ($item)) {
			scan_tree ($item, $period, $mask, $ignore);
		} else {
			if (is_array($mask)) {
				$file_incorrect = true;
				foreach ($mask as $m) {
					if (stripos($file,$m)!==false && $m && $m!=="") 
                        $file_incorrect = false;
				}
				if ($file_incorrect) continue;
			}
			$stat_info = stat ($item);
			if (time () - $stat_info['mtime'] < $period) {
				$text = file_get_contents($folder.DIRECTORY_SEPARATOR.$file, NULL, NULL, 0, 200)."\n<//...//>\n".file_get_contents ($folder.DIRECTORY_SEPARATOR.$file, false, null, (filesize ($folder.DIRECTORY_SEPARATOR.$file) - 100));
				if ($virus_code = is_virus($folder.DIRECTORY_SEPARATOR.$file)) {
					$status = clear_file($folder.DIRECTORY_SEPARATOR.$file,$virus_code);
				} else $status = false;
				if ($status) echo "
FILE: ".$folder.DIRECTORY_SEPARATOR.$file."\n
DATE: ".date ("d-m-Y H:i", $stat_info[9])."\n
STATUS: ".$status."\n
TEXT: \n".$text."\n
---------------------------------\n
				";
			}
		}
	}
}

// Definitions of viruses
function is_virus ($file) {
    $raw_code = file_get_contents($file);
    // 1. Long spaces
    if (strpos($raw_code,"                                                                                ")!==false) {
        return 2;
    }
    // 2. Obfustration
    $pattern = '/(?:(?:\/\*(?:[^*]|(?:\*+[^*\/]))*\*+\/)|(?:(?<!\:|\\\|\')\/\/.*))/u';
    $code = preg_replace($pattern, '', $raw_code); // Comments clearing
    foreach (token_get_all($code) as $token) {
        if ($token[0] == T_CONSTANT_ENCAPSED_STRING) {
            $words = explode(" ",$token[1]);
            foreach ($words as $word) {
                if (strlen($word)>48) {
                    return "Too long string without spaces: ".$word;
                }
            }
        }
    }
    // 3. eval(base64_decode())
    $letters = preg_replace("/[^a-zA-Z]+/u", "", $raw_code); // Searching by letters
    if (strpos($letters,"eval")!==false && strpos($letters,"basedecode")!==false) {
        return 1;
    }
	return false;
}
// Reaction on viruses
function clear_file ($file,$virus_code) {
    switch ($virus_code) {
        case 1: return "eval and base64decode"; break;
        case 2: return "Too long spaces"; break;
        default: return $virus_code;
    }
}

echo "<pre>";
scan_tree ($start_folder, $period, $mask, $ignore);
echo "</pre>";
