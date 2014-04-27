/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2013 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.0 of the PHP license,       |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_0.txt.                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: John Coggeshall <john@php.net>                               |
  |         Giuseppe Chiesa <mail@giuseppechiesa.it>					 |
  +----------------------------------------------------------------------+
*/

/*
 * BLENC_PROTECT.H 
 */
#ifndef BLENC_PROTECT_H
#define BLENC_PROTECT_H

/*
 * BLENC_PROTECT_COMP3 : It's a better way to protect the expiration date into the module executable 
 *						 and preventing reverse engineering.
 * 						 With this declaration the expiration date must be into the comp3 format.
 *					     Please see below for further informations. 
 */
#define BLENC_PROTECT_COMP3

/*
 * BLENC_PROTECT_MAIN_KEY : It's the encryption key used to encode the keyfile available for powerusers on the 
 * 							system. With this key hard encoded nobody could be able to decrypt the PHP sources 
 * 							protected with BLENC.
 *							Use a strong key!
 *							ex: create a strong key using apg with command 
 *							~$ apg -a1 -m32 -x32 -E "\\\/\"" 
 */
#define BLENC_PROTECT_MAIN_KEY 	"0123456789abcdef0123456789abcdef"

/*
 * BLENC_PROTECT_EXPIRE : It's the expiration date for the module extension. After this date the module will not 
 * 						  decrypt sources.
 *						  The date must have different formats according with BLENC_PROTECT_COMP3 definition: 
 *						  - If BLENC_PROTECT_COMP3 is undefined the date must be in the format: 
 * 							GG-MM-AAAA
 * 							(ex. 30-04-2013)
 * #define BLENC_PROTECT_EXPIRE	"30-04-2013"
 *
 *
 *						  - If BLENC_PROTECT COMP3 id defined the date must follow the comp3 compression (stronger against
 *							reverse engineering techniques). The format is the following: 
 *							{ '\xAA', '\xAA', '\xMM', '\xGG' }
 *
 *							ex. 30-04-2013 -> { '\x20', '\x13', '\x04', '\x30' }
 */
#define BLENC_PROTECT_EXPIRE 	{ '\x99', '\x99', '\x99', '\x99' }

#endif
