/**
 * ============================================================================
 * TOTP Authenticator for M5Stack Cardputer ADV
 * Copyright (c) 2026 chillyc0de
 * Licensed under the MIT License.
 * * This software incorporates components from the following third-party works:
 * - ArduinoJson: Copyright (c) 2014-2025 Benoit BLANCHON (MIT License)
 * - TOTP-Arduino: Copyright (c) Luca Dentella (Apache License 2.0)
 * - QRCode: Copyright (c) 2017 Richard Moore, Project Nayuki (MIT License)
 * - AESLib: Copyright (c) 1998-2008 Brian Gladman, Mark Tillotson (Custom permissive)
 * - M5Cardputer: Copyright (c) M5Stack (SDK)
 * * See the NOTICE.txt and LICENSE file in the repository for full license texts.
 * ============================================================================
 */

#include "USB.h"
#include "USBHIDKeyboard.h"
#undef KEY_BACKSPACE
#undef KEY_TAB
#include <M5Cardputer.h>

#include "qrcode.h"
#include <ArduinoJson.h>
#include <Preferences.h>
#include <SD.h>
// #include <vector>

#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"

#define MINIMUM_UNIX_TS 1773532800
#define MINIMUM_DATE "20260315000000"
#define DEFAULT_UTC 3
#define DEFAULT_BRIGHTNESS 130
#define DEFAULT_VOLUME 80
#define DEFAULT_SOUND_ES false
#define DEFAULT_SOUND_KBD 1
#define DEFAULT_SOUND_SCR true
#define DEFAULT_SOUND_TOTP 1

const char *DATA_FILE_PATH = "/by_chillyc0de/TOTP_Auth/data";
const char *SCREENSHOTS_DIR_PATH = "/by_chillyc0de/TOTP_Auth/screenshots/";
const char *FIRMWARE_VERSION = "v1.3.3";

const int SCREEN_WIDTH = 240;
const int SCREEN_HEIGHT = 135;

const uint16_t UI_BG = 0x0000;
const uint16_t UI_FG = 0xFFFF;
const uint16_t UI_ACCENT = 0xE204;
const uint16_t UI_MUTED = 0x39E7;
const uint16_t UI_DANGER = 0xF800;
const uint16_t UI_VALID = 0x07E0;

const int MAX_BASE32_DECODE_LENGTH = 128;
const int MAX_ACCOUNT_NAME_LENGTH = 32;

const String userGuideLines[] = {
    "============ TOTP AUTH ============",
    " Created by chillyc0de.",
    " Assisted by Google Gemini (LLM).",
    " Offline hardware authenticator",
    " for M5Stack Cardputer ADV.",
    "",
    "------- 1. GETTING  STARTED -------",
    " 1. Enter your Master Password.",
    " 2. Set accurate Date, Time",
    "    and UTC offset for sync.",
    "",
    "----------- 2. ACCOUNTS -----------",
    " Secret Keys must be Base32",
    " (A-Z, 2-7 only).",
    " View: Generate code.",
    " QR: Display for migration.",
    " Edit/Delete: Manage vault.",
    "",
    "-------- 3. USB  AUTO-TYPE --------",
    " Connect Cardputer to PC via USB.",
    " In the 'View TOTP' screen,",
    " press [Enter] to auto-type the",
    " code (USB-HID keyboard mode).",
    "",
    "-------- 4. AUDIO FEEDBACK --------",
    " Navigation: Unique tone patterns",
    " for each screen transition.",
    " Codes: Morse audio for TOTP.",
    " Modes: Switch between Morse or",
    " simple tones in Sound Settings.",
    "",
    "-------- 5. SCREENSHOTS ---------",
    " Press [BtnGO] to capture screen.",
    " Saved as .bmp to SD card.",
    " Folder path: /by_chillyc0de/TOTP_Auth/screenshots/",
    " Useful for debugging & logs.",
    "",
    "----------- 6. SECURITY -----------",
    " Vault: AES-256 encrypted.",
    " File path: /by_chillyc0de/TOTP_Auth/data",
    " NO PASSWORD RECOVERY! If you",
    " forget it, data is lost.",
    "",
    "---------- 7. SETTINGS -----------",
    " Press [Esc] in Account list:",
    " * Time setup: Re-sync clock.",
    " * Brightness: Adjust backlight.",
    " * Volume: Speaker loudness.",
    " * Sound type: Tones vs Morse.",
    " * Password: Set new master key.",
    "",
    "------- 8. LICENSE & RIGHTS -------",
    " Provided 'AS IS' under MIT License.",
    " Use at your own risk. The author",
    " is not responsible for lost data",
    " or locked accounts.",
};
const int userGuideLinesSize = sizeof(userGuideLines) / sizeof(userGuideLines[0]);

enum ExternalState : uint8_t {
    STATE_SPLASH_SCREEN,
    STATE_GUIDE,
    STATE_LOGIN,
    STATE_TIME_SETUP,
    STATE_SETTINGS_MENU,
    STATE_CHANGE_PASSWORD,
    STATE_BRIGHTNESS_SETUP,
    STATE_VOLUME_SETUP,
    STATE_SOUND_SETUP,
    STATE_ACCOUNT_LIST,
    STATE_ACTION_MENU,
    STATE_ADD_EDIT_ACCOUNT,
    STATE_DELETE_ACCOUNT,
    STATE_VIEW_TOTP,
    STATE_VIEW_QR
};

struct InternalState {
    ExternalState currentExternalState = STATE_SPLASH_SCREEN;
    bool requiresRedraw = true;

    // Guide
    int guideScrollY = 0;
    int guideScrollX = 0;

    // Login
    uint8_t salt[16];
    bool isSaltInitialized = false;
    bool isLoggedIn = false;

    String loginPasswordInput = "";
    bool loginShowPassword = false;
    int loginCursorPosition = 0;
    int loginScrollOffset = 0;
    ulong loginErrorClearTime = 0;

    // Time setup
    String timeSetupTimeInput = MINIMUM_DATE;
    int timeSetupUTCOffsetInput = DEFAULT_UTC;

    // Settings menu
    int settingsMenuSelectedIndex = 0;
    int settingsMenuScrollOffset = 0;
    bool initialTimeSetupDone = false;

    // Brightness setup
    int brightnessSetupBrightnessCounter = DEFAULT_BRIGHTNESS;

    // Volume setup
    int volumeSetupVolumeCounter = DEFAULT_VOLUME;

    // Sound setup
    int soundSetupFieldIdx = 0;
    bool soundSetupExternalState = DEFAULT_SOUND_ES;
    int soundSetupKeyboard = DEFAULT_SOUND_KBD;
    int soundSetupTOTP = DEFAULT_SOUND_TOTP;
    bool soundSetupScreenshot = DEFAULT_SOUND_SCR;

    // Change password
    String changePasswordInput = "";
    bool changePasswordShowPassword = false;
    int changePasswordCursorPosition = 0;
    int changePasswordScrollOffset = 0;

    // Account list
    int accountListSelectedIndex = 0;
    int accountListScrollOffset = 0;

    // Action menu
    int actionMenuSelectedIndex = 0;
    int actionMenuScrollOffset = 0;

    // Add / Edit account
    bool isEditMode = false;
    int addEditAccountFieldIdx = 0;
    String addEditAccountNameInput = "";
    String addEditAccountKeyInput = "";
    int addEditAccountAlgoInput = 0;
    int addEditAccountDigitsInput = 6;
    int addEditAccountPeriodInput = 30;
};

struct Account {
    String name;
    String key;
    int algo;
    int digits;
    int period;
};
std::vector<Account> savedAccounts;

USBHIDKeyboard usbKeyboard;
LGFX_Sprite displaySprite(&M5.Lcd);
Preferences systemPreferences;
InternalState internalState;

// --- ЗВУКОВАЯ ИНДИКАЦИЯ ---
void playMorse(const char *code, float freq, uint32_t dot, uint32_t dash, uint32_t pause) {
    while (*code) {
        if (*code == '.') M5.Speaker.tone(freq, dot);
        else if (*code == '-') M5.Speaker.tone(freq, dash);
        delay(pause);
        code++;
    }
}

void playMorseTone(char kChar, Keyboard_Class::KeysState kState = {}) {
    if (internalState.volumeSetupVolumeCounter == 0) return;

    float frequency = 1000;
    const uint32_t dot_duration = 50;
    const uint32_t dash_duration = 150;
    const uint32_t pause_duration = 60;

    const char *morse = nullptr;

    // Комбинации Fn
    if (kState.fn) {
        frequency = 1400;

        if (kChar == ';') morse = "..-";             // U (UP)
        else if (kChar == '.') morse = "-..";        // D (DOWN)
        else if (kChar == ',') morse = ".-..";       // L (LEFT)
        else if (kChar == '/') morse = ".-.";        // R (RIGHT)
        else if (kChar == '`') morse = ". ... -.-."; // ESC
        else if (kState.del) morse = "-.. . .-..";   // DEL

        if (morse) {
            playMorse(morse, frequency, dot_duration, dash_duration, pause_duration);
            return;
        }
    }

    // Клавиши состояния
    if (kState.enter) {
        frequency = 1200;
        playMorse(".", frequency, dot_duration, dash_duration, pause_duration);  // E
        playMorse("-.", frequency, dot_duration, dash_duration, pause_duration); // N
        return;
    }
    if (kState.tab) {
        frequency = 1200;
        playMorse("-", frequency, dot_duration, dash_duration, pause_duration);    // T
        playMorse(".-", frequency, dot_duration, dash_duration, pause_duration);   // A
        playMorse("-...", frequency, dot_duration, dash_duration, pause_duration); // B
        return;
    }
    if (kState.del && !kState.fn) {
        frequency = 1200;
        playMorse("-...", frequency, dot_duration, dash_duration, pause_duration); // B
        return;
    }
    // Пробел
    if (kChar == ' ') {
        frequency = 900;
        playMorse("...", frequency, dot_duration, dash_duration, pause_duration);  // S
        playMorse(".--.", frequency, dot_duration, dash_duration, pause_duration); // P
        return;
    }

    // Символы
    switch (tolower(kChar)) {
    // Буквы
    case 'a':
        morse = ".-";
        break;
    case 'b':
        morse = "-...";
        break;
    case 'c':
        morse = "-.-.";
        break;
    case 'd':
        morse = "-..";
        break;
    case 'e':
        morse = ".";
        break;
    case 'f':
        morse = "..-.";
        break;
    case 'g':
        morse = "--.";
        break;
    case 'h':
        morse = "....";
        break;
    case 'i':
        morse = "..";
        break;
    case 'j':
        morse = ".---";
        break;
    case 'k':
        morse = "-.-";
        break;
    case 'l':
        morse = ".-..";
        break;
    case 'm':
        morse = "--";
        break;
    case 'n':
        morse = "-.";
        break;
    case 'o':
        morse = "---";
        break;
    case 'p':
        morse = ".--.";
        break;
    case 'q':
        morse = "--.-";
        break;
    case 'r':
        morse = ".-.";
        break;
    case 's':
        morse = "...";
        break;
    case 't':
        morse = "-";
        break;
    case 'u':
        morse = "..-";
        break;
    case 'v':
        morse = "...-";
        break;
    case 'w':
        morse = ".--";
        break;
    case 'x':
        morse = "-..-";
        break;
    case 'y':
        morse = "-.--";
        break;
    case 'z':
        morse = "--..";
        break;

    // Цифры
    case '1':
        morse = ".----";
        break;
    case '2':
        morse = "..---";
        break;
    case '3':
        morse = "...--";
        break;
    case '4':
        morse = "....-";
        break;
    case '5':
        morse = ".....";
        break;
    case '6':
        morse = "-....";
        break;
    case '7':
        morse = "--...";
        break;
    case '8':
        morse = "---..";
        break;
    case '9':
        morse = "----.";
        break;
    case '0':
        morse = "-----";
        break;

    // Спецсимволы
    case '.':
        morse = ".-.-.-";
        break;
    case ',':
        morse = "--..--";
        break;
    case '?':
        morse = "..--..";
        break;
    case '!':
        morse = "-.-.--";
        break;
    case ':':
        morse = "---...";
        break;
    case ';':
        morse = "-.-.-.";
        break;
    case '=':
        morse = "-...-";
        break;
    case '-':
        morse = "-....-";
        break;
    case '_':
        morse = "..--.-";
        break;
    case '"':
        morse = ".-..-.";
        break;
    case '\'':
        morse = ".----.";
        break;
    case '/':
        morse = "-..-.";
        break;
    case '(':
        morse = "-.--.";
        break;
    case ')':
        morse = "-.--.-";
        break;
    case '+':
        morse = ".-.-.";
        break;
    case '@':
        morse = ".--.-.";
        break;

    default:
        break;
    }

    if (morse) playMorse(morse, frequency, dot_duration, dash_duration, pause_duration);
    else M5.Speaker.tone(frequency, 25);
}

void playMorseTOTPCode(const String &totpCode) {
    if (internalState.volumeSetupVolumeCounter == 0) return;
    for (int i = 0; i < totpCode.length(); i++) {
        playMorseTone(totpCode[i]);
        delay(100);
    }
}

void playKeyTone(char kChar, Keyboard_Class::KeysState kState = {}) {
    if (internalState.volumeSetupVolumeCounter == 0) return;

    float frequency = 1000;
    const uint32_t duration = 40;

    // --- Комбинации Fn ---
    if (kState.fn) {
        if (kChar == ';') frequency = 1400;      // UP
        else if (kChar == '.') frequency = 1350; // DOWN
        else if (kChar == ',') frequency = 1300; // LEFT
        else if (kChar == '/') frequency = 1250; // RIGHT
        else if (kChar == '`') frequency = 1500; // ESCAPE
        else if (kState.del) frequency = 1200;   // DELETE

        M5.Speaker.tone(frequency, duration);
        return;
    }

    // Клавиши состояния
    if (kState.enter) frequency = 1200;
    else if (kState.tab) frequency = 1100;
    else if (kState.del) frequency = 1000;

    // Пробел
    else if (kChar == ' ') frequency = 900;

    // Символы
    else {
        switch (tolower(kChar)) {
        case 'a':
        case 'b':
        case 'c':
            frequency = 1000;
            break;
        case 'd':
        case 'e':
        case 'f':
            frequency = 1050;
            break;
        case 'g':
        case 'h':
        case 'i':
            frequency = 1100;
            break;
        case 'j':
        case 'k':
        case 'l':
            frequency = 1150;
            break;
        case 'm':
        case 'n':
        case 'o':
            frequency = 1200;
            break;
        case 'p':
        case 'q':
        case 'r':
        case 's':
            frequency = 1250;
            break;
        case 't':
        case 'u':
        case 'v':
            frequency = 1300;
            break;
        case 'w':
        case 'x':
        case 'y':
        case 'z':
            frequency = 1350;
            break;
        case '0':
        case '1':
        case '2':
            frequency = 900;
            break;
        case '3':
        case '4':
        case '5':
            frequency = 950;
            break;
        case '6':
        case '7':
        case '8':
            frequency = 1000;
            break;
        case '9':
            frequency = 1050;
            break;
            // Спецсимволы
        default:
            frequency = 950;
            break;
        }
    }

    M5.Speaker.tone(frequency, duration);
}

void playExternalStateTone(ExternalState externalState) {
    if (internalState.volumeSetupVolumeCounter == 0) return;

    switch (externalState) {
    case STATE_SPLASH_SCREEN:
        M5.Speaker.tone(700, 80);
        delay(80);
        M5.Speaker.tone(900, 80);
        break;
    case STATE_GUIDE:
        M5.Speaker.tone(600, 100);
        delay(100);
        M5.Speaker.tone(800, 100);
        break;
    case STATE_LOGIN:
        M5.Speaker.tone(800, 60);
        delay(60);
        M5.Speaker.tone(1000, 60);
        break;
    case STATE_TIME_SETUP:
        M5.Speaker.tone(750, 60);
        delay(100);
        M5.Speaker.tone(1000, 60);
        delay(100);
        M5.Speaker.tone(750, 60);
        break;
    case STATE_SETTINGS_MENU:
        M5.Speaker.tone(750, 60);
        delay(60);
        M5.Speaker.tone(900, 60);
        delay(60);
        M5.Speaker.tone(1050, 60);
        break;
    case STATE_CHANGE_PASSWORD:
        M5.Speaker.tone(750, 60);
        delay(60);
        M5.Speaker.tone(500, 100);
        break;
    case STATE_BRIGHTNESS_SETUP:
        M5.Speaker.tone(750, 60);
        delay(60);
        M5.Speaker.tone(1300, 60);
        break;
    case STATE_VOLUME_SETUP:
        M5.Speaker.tone(750, 60);
        delay(60);
        M5.Speaker.tone(550, 60);
        break;
    case STATE_SOUND_SETUP:
        M5.Speaker.tone(750, 60);
        delay(60);
        M5.Speaker.tone(850, 40);
        delay(40);
        M5.Speaker.tone(750, 60);
        break;
    case STATE_ACCOUNT_LIST:
        M5.Speaker.tone(850, 60);
        delay(60);
        M5.Speaker.tone(1050, 80);
        break;
    case STATE_ACTION_MENU:
        M5.Speaker.tone(1050, 60);
        delay(60);
        M5.Speaker.tone(1200, 60);
        break;
    case STATE_ADD_EDIT_ACCOUNT:
        M5.Speaker.tone(1050, 60);
        delay(60);
        M5.Speaker.tone(1500, 80);
        break;
    case STATE_DELETE_ACCOUNT:
        M5.Speaker.tone(1050, 80);
        delay(80);
        M5.Speaker.tone(500, 150);
        break;
    case STATE_VIEW_TOTP:
        M5.Speaker.tone(1050, 60);
        delay(60);
        M5.Speaker.tone(1350, 120);
        break;
    case STATE_VIEW_QR:
        M5.Speaker.tone(1050, 50);
        delay(50);
        M5.Speaker.tone(1150, 50);
        delay(50);
        M5.Speaker.tone(1250, 50);
        break;
    }
}

// --- ПЕРЕКЛЮЧЕНИЕ ЭКРАНОВ ---
void switchExternalState(ExternalState externalState) {
    internalState.currentExternalState = externalState;
    internalState.requiresRedraw = true;

    // Подстановка текущего времени
    if (externalState == STATE_TIME_SETUP) {
        time_t nowTime = time(NULL);
        if (nowTime < MINIMUM_UNIX_TS) {
            internalState.timeSetupTimeInput = systemPreferences.getString("TA/time", MINIMUM_DATE);
            internalState.timeSetupUTCOffsetInput = systemPreferences.getInt("TA/utc", DEFAULT_UTC);
        } else {
            time_t localTime = nowTime + (internalState.timeSetupUTCOffsetInput * 3600);
            struct tm *t = gmtime(&localTime);
            char buf[16];
            strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", t);
            internalState.timeSetupTimeInput = String(buf);
        }
    }

    // Звуковая индикация
    if (internalState.soundSetupExternalState) playExternalStateTone(externalState);
}

// --- СТАТИЧНЫЕ МЕНЮ ---
struct MenuOption {
    String label;
    std::function<void()> action;
};

const MenuOption settingsMenuOptions[] = {
    {
        "[Enter]: Return to accounts",
        []() {
            switchExternalState(STATE_ACCOUNT_LIST);
        },
    },
    {
        "Time setup",
        []() {
            switchExternalState(STATE_TIME_SETUP);
        },
    },
    {
        "Brightness setup",
        []() {
            switchExternalState(STATE_BRIGHTNESS_SETUP);
        },
    },
    {
        "Volume setup",
        []() {
            switchExternalState(STATE_VOLUME_SETUP);
        },
    },
    {
        "Sound setup",
        []() {
            switchExternalState(STATE_SOUND_SETUP);
        },
    },
    {
        "Change password",
        []() {
            switchExternalState(STATE_CHANGE_PASSWORD);
        },
    },
};
const int settingsMenuOptionsSize = sizeof(settingsMenuOptions) / sizeof(settingsMenuOptions[0]);

const MenuOption actionMenuOptions[] = {
    {
        "View TOTP Code",
        []() {
            switchExternalState(STATE_VIEW_TOTP);
        },
    },
    {
        "Show QR Code",
        []() {
            switchExternalState(STATE_VIEW_QR);
        },
    },
    {
        "Edit Account",
        []() {
            Account acc = savedAccounts[internalState.accountListSelectedIndex - 1];
            internalState.addEditAccountNameInput = acc.name;
            internalState.addEditAccountKeyInput = acc.key;
            internalState.addEditAccountAlgoInput = acc.algo;
            internalState.addEditAccountDigitsInput = acc.digits;
            internalState.addEditAccountPeriodInput = acc.period;
            internalState.isEditMode = true;
            internalState.addEditAccountFieldIdx = 0;
            switchExternalState(STATE_ADD_EDIT_ACCOUNT);
        },
    },
    {
        "Delete Account",
        []() {
            switchExternalState(STATE_DELETE_ACCOUNT);
        },
    },
};
const int actionMenuOptionsSize = sizeof(actionMenuOptions) / sizeof(actionMenuOptions[0]);

// --- КРИПТОГРАФИЧЕСКИЕ ФУНКЦИИ ---
void deriveKey(const String &password, const uint8_t *salt, uint8_t *key) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_pkcs5_pbkdf2_hmac(&ctx, (const unsigned char *)password.c_str(), password.length(), salt, 16, 10000, 32, key);
    mbedtls_md_free(&ctx);
}

int decodeBase32String(const char *encodedString, uint8_t *resultBuffer) {
    int bitBuffer = 0, bitsLeft = 0, byteCount = 0;
    for (const char *ptr = encodedString; *ptr; ++ptr) {
        uint8_t c = toupper(*ptr);
        if (isspace(c) || c == '=' || c == '-') continue;

        uint8_t val = (c >= 'A' && c <= 'Z') ? c - 'A' : (c >= '2' && c <= '7') ? c - '2' + 26
                                                                                : 0xFF;
        if (val == 0xFF) continue;

        bitBuffer = (bitBuffer << 5) | val;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            resultBuffer[byteCount++] = (bitBuffer >> (bitsLeft - 8)) & 0xFF;
            bitsLeft -= 8;
        }
    }
    if (bitsLeft > 0 && byteCount < MAX_BASE32_DECODE_LENGTH) resultBuffer[byteCount++] = (bitBuffer << (8 - bitsLeft)) & 0xFF;
    return byteCount;
}

String generateTOTP(const String &base32Secret, int algo, int digits, int period, time_t now) {
    uint8_t key[MAX_BASE32_DECODE_LENGTH];
    int keyLen = decodeBase32String(base32Secret.c_str(), key);
    if (keyLen == 0) return "ERROR";

    uint64_t counter = now / period;
    uint8_t counterBytes[8];
    for (int i = 7; i >= 0; i--) {
        counterBytes[i] = counter & 0xFF;
        counter >>= 8;
    }

    mbedtls_md_type_t md_type = (algo == 1) ? MBEDTLS_MD_SHA256 : (algo == 2) ? MBEDTLS_MD_SHA512
                                                                              : MBEDTLS_MD_SHA1;
    uint8_t hash[64];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, key, keyLen);
    mbedtls_md_hmac_update(&ctx, counterBytes, 8);
    mbedtls_md_hmac_finish(&ctx, hash);
    mbedtls_md_free(&ctx);

    int offset = hash[mbedtls_md_get_size(mbedtls_md_info_from_type(md_type)) - 1] & 0x0F;
    uint32_t binary = ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16) | ((hash[offset + 2] & 0xFF) << 8) | (hash[offset + 3] & 0xFF);

    uint32_t otp = binary % (digits == 8 ? 100000000 : 1000000);
    char format[10], result[12]; // Взял result с запасом
    snprintf(format, sizeof(format), "%%0%dd", digits);
    snprintf(result, sizeof(result), format, otp);
    return String(result);
}

// --- ФУНКЦИИ ДЛЯ ВАЛИДАЦИИ ---
String urlEncode(const String &str) {
    String encodedString = "";
    char c, code0, code1;
    for (int i = 0; i < str.length(); i++) {
        c = str.charAt(i);
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') encodedString += c;
        else {
            code1 = (c & 0xf) + '0';
            if ((c & 0xf) > 9) code1 = (c & 0xf) - 10 + 'A';
            c = (c >> 4) & 0xf;
            code0 = c + '0';
            if (c > 9) code0 = c - 10 + 'A';
            encodedString += '%';
            encodedString += code0;
            encodedString += code1;
        }
    }
    return encodedString;
}

bool isNextDateTimeDigitValid(const String &currentString, char nextDigit) {
    String potentialString = currentString + nextDigit;
    int length = potentialString.length();
    int position = currentString.length();
    int digitValue = nextDigit - '0';

    if (potentialString < ((String)MINIMUM_DATE).substring(0, length)) return false;
    if (position < 4) return true;
    if (position == 4) return (digitValue == 0 || digitValue == 1);
    if (position == 5) return (currentString[4] - '0' == 0) ? (digitValue >= 1 && digitValue <= 9) : (digitValue >= 0 && digitValue <= 2);
    if (position == 6) return (digitValue > 3) ? false : (potentialString.substring(4, 6).toInt() == 2) ? (digitValue <= 2)
                                                                                                        : true;
    if (position == 7) {
        int year = potentialString.substring(0, 4).toInt();
        int month = potentialString.substring(4, 6).toInt();
        int day = potentialString.substring(6, 8).toInt();
        if (day < 1) return false;

        int maxDaysInMonth[] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        if (month == 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))) maxDaysInMonth[2] = 29;
        return (day <= maxDaysInMonth[month]);
    }
    if (position == 8) return (digitValue <= 2);
    if (position == 9) return (potentialString.substring(8, 10).toInt() <= 23);
    if (position == 10 || position == 12) return (digitValue <= 5);
    return true;
}

// --- ФУНКЦИИ ДЛЯ РАБОТЫ С ДАННЫМИ И ХРАНИЛИЩЕМ ---
void ensureDirectoryExists(const char *dirPath, bool isFilePath = false) {
    String fullPath = String(dirPath);

    // Если это путь к файлу, отрезаем имя файла
    if (isFilePath) {
        int lastSlash = fullPath.lastIndexOf('/');
        if (lastSlash != -1) fullPath = fullPath.substring(0, lastSlash);
    }

    // Убираем последний "/"
    if (fullPath.endsWith("/")) fullPath.remove(fullPath.length() - 1);

    String currentPath = "";
    // Не считаем ведущий "/"
    int currentIdx = fullPath.startsWith("/") ? 1 : 0;
    while (currentIdx < fullPath.length()) {
        int slashIdx = fullPath.indexOf('/', currentIdx);
        // Если слэшей больше нет, берем до конца строки
        if (slashIdx == -1) slashIdx = fullPath.length();

        currentPath = fullPath.substring(0, slashIdx);
        if (!SD.exists(currentPath)) SD.mkdir(currentPath);

        currentIdx = slashIdx + 1;
    }
}

bool readVaultFromSD(uint8_t *salt, uint8_t *iv, std::vector<uint8_t> &encBuf) {
    if (!SD.exists(DATA_FILE_PATH)) return false;

    File file = SD.open(DATA_FILE_PATH, FILE_READ);
    if (!file || file.size() < 32) {
        if (file) file.close();
        return false;
    }

    file.read(salt, 16);
    file.read(iv, 16);

    size_t encLen = file.size() - 32;
    if (encLen % 16 != 0 || encLen == 0) {
        file.close();
        return false;
    }

    encBuf.resize(encLen);
    file.read(encBuf.data(), encLen);
    file.close();
    return true;
}

bool parseVaultJSON(const std::vector<uint8_t> &decBuf) {
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, (const char *)decBuf.data(), decBuf.size());
    if (error) return false;

    savedAccounts.clear();
    for (JsonObject obj : doc.as<JsonArray>()) {
        Account acc;
        acc.name = obj["n"].as<String>();
        acc.key = obj["s"].as<String>();
        acc.algo = obj["a"].is<int>() ? obj["a"].as<int>() : 0;
        acc.digits = obj["d"].is<int>() ? obj["d"].as<int>() : 6;
        acc.period = obj["p"].is<int>() ? obj["p"].as<int>() : 30;
        savedAccounts.push_back(acc);
    }
    return true;
}

String serializeVaultJSON() {
    JsonDocument doc;
    JsonArray arr = doc.to<JsonArray>();
    for (const Account &acc : savedAccounts) {
        JsonObject obj = arr.add<JsonObject>();
        obj["n"] = acc.name;
        obj["s"] = acc.key;
        obj["a"] = acc.algo;
        obj["d"] = acc.digits;
        obj["p"] = acc.period;
    }
    String jsonStr;
    serializeJson(doc, jsonStr);
    return jsonStr;
}

bool decryptVault(const std::vector<uint8_t> &encBuf, const uint8_t *salt, const uint8_t *iv, const String &password, std::vector<uint8_t> &decBuf) {
    uint8_t key[32];
    deriveKey(password, salt, key);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 256);

    decBuf.resize(encBuf.size());
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, encBuf.size(), const_cast<uint8_t *>(iv), encBuf.data(), decBuf.data());
    mbedtls_aes_free(&aes);

    uint8_t padLen = decBuf.back();
    if (padLen > 16 || padLen == 0) return false;
    for (size_t i = encBuf.size() - padLen; i < encBuf.size(); i++) {
        if (decBuf[i] != padLen) return false;
    }

    decBuf.resize(encBuf.size() - padLen);
    return true;
}

void encryptVault(const String &jsonStr, const uint8_t *salt, const uint8_t *iv, const String &password, std::vector<uint8_t> &encBuf) {
    size_t origLen = jsonStr.length();
    uint8_t padLen = 16 - (origLen % 16);
    size_t paddedLen = origLen + padLen;

    std::vector<uint8_t> plainBuf(paddedLen);
    memcpy(plainBuf.data(), jsonStr.c_str(), origLen);
    for (size_t i = origLen; i < paddedLen; i++) plainBuf[i] = padLen;

    uint8_t key[32];
    deriveKey(password, salt, key);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 256);

    encBuf.resize(paddedLen);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedLen, const_cast<uint8_t *>(iv), plainBuf.data(), encBuf.data());
    mbedtls_aes_free(&aes);
}

bool loadAccountsFromStorage() {
    if (!SD.exists(DATA_FILE_PATH)) return true;

    uint8_t salt[16], iv[16];
    std::vector<uint8_t> encBuf, decBuf;

    if (!readVaultFromSD(salt, iv, encBuf)) return false;
    if (!decryptVault(encBuf, salt, iv, internalState.loginPasswordInput, decBuf)) return false;
    if (!parseVaultJSON(decBuf)) return false;

    memcpy(internalState.salt, salt, 16);
    internalState.isSaltInitialized = true;
    return true;
}

void writeVaultToSD(const uint8_t *salt, const uint8_t *iv, const std::vector<uint8_t> &encBuf) {
    ensureDirectoryExists(DATA_FILE_PATH, true);

    File file = SD.open(DATA_FILE_PATH, FILE_WRITE);
    if (file) {
        file.write(salt, 16);
        file.write(iv, 16);
        file.write(encBuf.data(), encBuf.size());
        file.close();
    }
}

void saveAccountsToStorage() {
    if (!internalState.isSaltInitialized) {
        esp_fill_random(internalState.salt, 16);
        internalState.isSaltInitialized = true;
    }

    uint8_t iv[16], orig_iv[16];
    esp_fill_random(orig_iv, 16);
    memcpy(iv, orig_iv, 16);

    String jsonStr = serializeVaultJSON();
    std::vector<uint8_t> encBuf;

    encryptVault(jsonStr, internalState.salt, iv, internalState.loginPasswordInput, encBuf);
    writeVaultToSD(internalState.salt, orig_iv, encBuf);
}

void performPasswordChange() {
    // Генерируем новую соль, чтобы старые хеши были бесполезны
    esp_fill_random(internalState.salt, 16);
    internalState.isSaltInitialized = true;

    // Обновляем основной пароль в памяти
    internalState.loginPasswordInput = internalState.changePasswordInput;

    // Очищаем поле ввода для будущих вызовов
    internalState.changePasswordInput = "";

    // Перезаписываем файл с новым ключом и новой солью
    saveAccountsToStorage();
}

// --- ОТРИСОВКА ВСПОМОГАТЕЛЬНЫХ ЭЛЕМЕНТОВ ---
void drawHeader(const String &title, const String &rightText = "") {
    displaySprite.fillRect(0, 0, SCREEN_WIDTH, 24, UI_ACCENT);
    displaySprite.setTextColor(UI_FG);

    if (rightText == "") {
        displaySprite.setTextDatum(middle_center);
        displaySprite.drawString(title, SCREEN_WIDTH / 2, 12, &fonts::Font2);
    } else {
        displaySprite.setTextDatum(middle_left);
        displaySprite.drawString(title, 10, 12, &fonts::Font2);
        displaySprite.setTextDatum(middle_right);
        displaySprite.drawString(rightText, SCREEN_WIDTH - 10, 12, &fonts::Font2);
    }
}

void drawFooter(const std::vector<String> &lines) {
    int numLines = lines.size();

    int lineHeight = 12;
    int padding = 6;

    int footerHeight = (numLines * lineHeight) + padding;

    displaySprite.fillRect(0, SCREEN_HEIGHT - footerHeight, SCREEN_WIDTH, footerHeight, UI_MUTED);
    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_left);

    int startY = (SCREEN_HEIGHT - footerHeight) + 9;
    for (int i = 0; i < numLines; i++) {
        int yPos = startY + (i * lineHeight);
        displaySprite.drawString(lines[i], 2, yPos, &fonts::Font0);
    }
}

void drawScrollbar(int current, int visible, int total, int yStart, int height) {
    if (total <= visible) return;
    int barHeight = max(10, (visible * height) / total);
    int maxTop = total - visible;
    int barY = yStart + (current * (height - barHeight)) / maxTop;
    displaySprite.fillRect(SCREEN_WIDTH - 4, yStart, 4, height, UI_BG);
    displaySprite.fillRect(SCREEN_WIDTH - 3, barY, 2, barHeight, UI_ACCENT);
}

void drawProgressBar(float progress, uint16_t fgColor = UI_ACCENT, uint16_t bgColor = UI_BG) {
    // progress от 0.0 до 1.0
    progress = max(0.0f, min(progress, 1.0f));

    // Обводка прогресс бара
    int w = SCREEN_WIDTH;
    int h = 12; // Высота бара
    int x = 0;
    int y = SCREEN_HEIGHT - h - 18;
    displaySprite.drawRect(x, y, w, h, UI_FG);

    // Внутреннее пространство
    displaySprite.fillRect(x + 1, y + 1, w - 2, h - 2, bgColor);

    // Заливка полосы прогресса
    int fillW = (int)((w - 4) * progress);
    if (fillW > 0) displaySprite.fillRect(x + 2, y + 2, fillW, h - 4, fgColor);
}

struct MessageLine {
    String text;
    const lgfx::IFont *fontPtr;
    MessageLine(const char *t, const lgfx::IFont *f = &fonts::Font4) : text(t), fontPtr(f) {}
    MessageLine(String t, const lgfx::IFont *f = &fonts::Font4) : text(t), fontPtr(f) {}
};
void drawMessage(const std::vector<MessageLine> &lines, uint16_t fgColor = UI_FG, uint16_t bgColor = UI_BG) {
    int numLines = std::min((int)lines.size(), 3);
    int lineHeight = 30; // Расстояние между центрами строк

    displaySprite.fillSprite(bgColor);
    displaySprite.setTextColor(fgColor);
    displaySprite.setTextDatum(middle_center);

    int startY = (SCREEN_HEIGHT / 2) - ((numLines - 1) * lineHeight / 2);
    for (int i = 0; i < numLines; i++) {
        int yPos = startY + (i * lineHeight);
        displaySprite.drawString(lines[i].text, SCREEN_WIDTH / 2, yPos, lines[i].fontPtr);
    }
    displaySprite.pushSprite(0, 0);
    internalState.requiresRedraw = false;
}

// --- ОТРИСОВКА ЭКРАНОВ ---
void renderSplashScreen() {
    displaySprite.fillSprite(UI_BG);
    drawFooter({"   [Any]: Guide      [Enter]: Login"});

    int iconSize = 30;
    int gap = 10;
    int textW = 120;
    int padding = 10;

    // Вычисляем общую ширину рамки
    int rectW = iconSize + gap + textW + (padding * 2);
    int rectH = 40;
    int rectX = (SCREEN_WIDTH - rectW) / 2;
    int rectY = 25;

    // Рисуем двойную рамку
    displaySprite.drawRoundRect(rectX, rectY, rectW, rectH, 8, 0xF800);
    displaySprite.drawRoundRect(rectX - 1, rectY - 1, rectW + 2, rectH + 2, 8, 0xF800);

    int ix = rectX + padding;
    int iy = rectY + (rectH - iconSize) / 2;

    // Фон иконки
    displaySprite.drawRect(ix, iy, iconSize, iconSize, UI_FG);
    displaySprite.fillRect(ix + 1, iy + 1, iconSize - 2, iconSize - 2, 0x0210); // Темно-синий

    // Анимация иконки
    ulong animTime = millis();
    // Генерируем "случайную" цифру на основе времени (меняется каждые 100мс)
    int digit = (animTime / 100) % 10;

    displaySprite.setTextColor(0x07E0); // Зеленый цвет для цифр
    displaySprite.setTextDatum(middle_center);
    displaySprite.drawString(String(digit), ix + (iconSize / 2), iy + (iconSize / 2) + 2, &fonts::Font4);

    // Эффект "сканирующей линии" поверх цифры
    int scanLineY = (animTime / 5) % (iconSize - 4);
    displaySprite.fillRect(ix + 2, iy + 2 + scanLineY, iconSize - 4, 1, 0x0410);

    // Текст заголовка
    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_left);
    displaySprite.drawString("TOTP Auth", ix + iconSize + gap, rectY + (rectH / 2) + 2, &fonts::Font4);

    // Координаты подписей
    int margin = 12;
    int labelX = SCREEN_WIDTH - margin;
    int labelY = SCREEN_HEIGHT - margin - 20;

    displaySprite.setTextColor(0x39E7);
    displaySprite.setTextDatum(bottom_left);
    displaySprite.drawString(FIRMWARE_VERSION, margin, labelY, &fonts::Font0);

    displaySprite.setTextColor(0xFD20);
    displaySprite.setTextDatum(bottom_right);
    displaySprite.drawString("by chillyc0de", labelX, labelY, &fonts::Font2);

    // Пиксельный перец
    int px = labelX - 105;
    int py = labelY - 14;
    int s = 3; // Размер блока перца

    // Тело перца (блоки)
    displaySprite.fillRect(px, py, s * 2, s * 2, 0xF800);                     // Основание
    displaySprite.fillRect(px + s, py + s * 1.5, s * 2.5, s * 2, 0xF800);     // Середина
    displaySprite.fillRect(px + s * 2, py + s * 3, s * 2.5, s * 1.5, 0xD000); // Изгиб
    displaySprite.fillRect(px + s * 4, py + s * 4, s * 1.5, s, 0xA000);       // Кончик

    // Хвостик перца
    displaySprite.fillRect(px, py - s, s * 1.5, s, 0x03E0);
    displaySprite.fillRect(px - s, py - s * 2, s, s, 0x03E0);

    // Пиксельный огонь (8 частиц)
    for (int i = 0; i < 8; i++) {
        ulong t = millis() + (i * 200); // Тайминг
        float duration = 600.0 + (i * 100.0);
        float anim = (float)(t % (int)duration) / duration;

        int lift, stepX, particleW;
        uint16_t fCol;

        // Центрируем "сопло" относительно основания перца
        int nozzleX = px + s;

        // Логика поведения частиц
        if (i < 3) // ТРИ ЦЕНТРАЛЬНЫЕ ЧАСТИЦЫ
        {
            lift = anim * 28;                          // Высокий подъем
            stepX = (int)(sin(t * 0.02) * (anim * 2)); // Минимальное отклонение внизу, чуть больше вверху
            particleW = s + 1;                         // Самые толстые

            // Белый -> Оранжевый -> Красный
            if (anim < 0.2) fCol = 0xFFFF;
            else if (anim < 0.6) fCol = 0xFD20;
            else fCol = 0xFA60;
        } else if (i < 6) // БОКОВЫЕ ЯЗЫКИ
        {
            lift = anim * 22;
            // Расширение конусом: чем выше (больше anim), тем сильнее уход в сторону
            int side = (i % 2 == 0) ? 1 : -1;
            stepX = side * (s + (anim * 8));
            particleW = s;

            fCol = (anim < 0.4) ? 0xFD20 : 0xF800;
        } else // ИСКРЫ И ДЫМ
        {
            lift = anim * 35;
            stepX = (int)(sin(t * 0.01)) * 6;
            particleW = 1;

            if (anim < 0.5) fCol = 0xFA60;
            else fCol = 0x4208; // Дым
        }

        int fX = nozzleX + stepX;
        int fY = py - lift;

        if (anim < 0.9) {
            displaySprite.fillRect(fX, fY, particleW, particleW, fCol);

            // ЭФФЕКТ СВЕТОВОГО ПЯТНА
            if (anim < 0.1) displaySprite.fillRect(nozzleX - 1, py, (s * 2), 2, 0xFD20);
        }
    }
}

void renderGuideScreen() {
    displaySprite.fillSprite(UI_BG);
    drawHeader("GUIDE");
    drawScrollbar(internalState.guideScrollY / 18, (SCREEN_HEIGHT - 44) / 18, userGuideLinesSize, 26, SCREEN_HEIGHT - 44);
    drawFooter({"   [Esc]: Back      [Arrows]: Scroll"});

    displaySprite.setClipRect(0, 26, SCREEN_WIDTH - 5, SCREEN_HEIGHT - 44);

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(top_left);
    displaySprite.setFont(&fonts::Font2);

    for (int i = 0; i < userGuideLinesSize; i++) {
        int yPos = 30 + (i * 18) - internalState.guideScrollY;
        if (yPos > -18 && yPos < SCREEN_HEIGHT) displaySprite.drawString(userGuideLines[i], 5 - internalState.guideScrollX, yPos);
    }
    displaySprite.clearClipRect();
}

void renderLoginScreen() {
    if (internalState.loginErrorClearTime > 0) {
        drawMessage({"WRONG", "PASSWORD"}, UI_FG, UI_DANGER);
        delay(400);
        return;
    }

    const int charWidth = 24;
    const int maxCharsPerLine = 10;
    const int linesPerPage = 2;

    // Подготовка отображаемого текста
    String rawDisplay = internalState.loginPasswordInput;
    if (!internalState.loginShowPassword) {
        rawDisplay = "";
        for (int i = 0; i < (int)internalState.loginPasswordInput.length(); i++) rawDisplay += "*";
    }

    // Нарезка на строки
    std::vector<String> lines;
    if (rawDisplay.length() == 0) lines.push_back("");
    else {
        for (int i = 0; i < (int)rawDisplay.length(); i += maxCharsPerLine) {
            lines.push_back(rawDisplay.substring(i, min(i + maxCharsPerLine, (int)rawDisplay.length())));
        }
        // Если курсор на новой строке
        if (internalState.loginCursorPosition > 0 && internalState.loginCursorPosition % maxCharsPerLine == 0 && internalState.loginCursorPosition == (int)internalState.loginPasswordInput.length()) {
            lines.push_back("");
        }
    }

    // Авто-скролл
    int cursorLineIdx = internalState.loginCursorPosition / maxCharsPerLine;
    if (cursorLineIdx < internalState.loginScrollOffset) internalState.loginScrollOffset = cursorLineIdx;
    if (cursorLineIdx >= internalState.loginScrollOffset + linesPerPage) internalState.loginScrollOffset = cursorLineIdx - (linesPerPage - 1);

    displaySprite.fillSprite(UI_BG);
    drawHeader("LOGIN");
    drawFooter({" [Tab]: Show/Hide  [FN+Arrows]: Cursor", " [FN+Esc]: Guide   [Enter]: Confirm"});

    displaySprite.setTextColor(UI_VALID);
    displaySprite.setTextDatum(middle_center);

    // Вычисляем стартовую X-координату для центрирования всего БЛОКА (10 символов)
    int startX = (SCREEN_WIDTH - maxCharsPerLine * charWidth) / 2 + (charWidth / 2);
    for (int i = 0; i < linesPerPage; i++) {
        int lineIdx = internalState.loginScrollOffset + i;

        // Фиксированная Y-координата
        int yPos = (SCREEN_HEIGHT / 2 - 18) + (i * 36);

        // Отрисовка текста
        if (lineIdx < (int)lines.size()) {
            String txt = lines[lineIdx];
            for (int j = 0; j < (int)txt.length(); j++) {
                displaySprite.drawString(String(txt[j]), startX + (j * charWidth), yPos, &fonts::Font4);
            }
        }

        // Отрисовка курсора
        if ((millis() % 1000) < 400 && lineIdx == cursorLineIdx) {
            int cursorXInLine = internalState.loginCursorPosition % maxCharsPerLine;

            // Сдвигаем курсор на левый край текущей ячейки символа
            int cursorX = startX + (cursorXInLine * charWidth) - (charWidth / 2);

            // Рисуем курсор
            displaySprite.fillRect(cursorX, yPos - 12, 2, 24, UI_ACCENT);
        }
    }
}

void renderTimeSetupScreen() {
    String dateMask = "____ - __ - __";
    String timeMask = "__ : __ : __";
    for (int i = 0; i < (int)internalState.timeSetupTimeInput.length(); i++) {
        if (i < 8) {
            int pos = (i < 4) ? i : (i < 6) ? i + 3
                                            : i + 6;
            dateMask[pos] = internalState.timeSetupTimeInput[i];
        } else {
            int timeIdx = i - 8;
            int pos = (timeIdx < 2) ? timeIdx : (timeIdx < 4) ? timeIdx + 3
                                                              : timeIdx + 6;
            timeMask[pos] = internalState.timeSetupTimeInput[i];
        }
    }

    displaySprite.fillSprite(UI_BG);
    String utcString = "UTC" + String(internalState.timeSetupUTCOffsetInput >= 0 ? "+" : "") + String(internalState.timeSetupUTCOffsetInput);
    drawHeader("TIME SETUP", utcString);
    drawFooter({"[Esc]: Back  [Arrows]: UTC [Enter]: Set"});

    displaySprite.setTextDatum(middle_center);
    displaySprite.setFont(&fonts::Font4);

    displaySprite.setTextColor(internalState.timeSetupTimeInput.length() >= 8 ? UI_VALID : UI_FG);
    displaySprite.drawString(dateMask, SCREEN_WIDTH / 2, 58);

    displaySprite.setTextColor(internalState.timeSetupTimeInput.length() == 14 ? UI_VALID : UI_FG);
    displaySprite.drawString(timeMask, SCREEN_WIDTH / 2, 93);
}

void renderSettingsMenuScreen() {
    displaySprite.fillSprite(UI_BG);
    drawHeader("SETTINGS");
    drawScrollbar(internalState.settingsMenuScrollOffset, 4, settingsMenuOptionsSize, 32, 4 * 20);
    drawFooter({"   [Esc]: Guide      [Enter]: Select"});

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_center);

    for (int i = 0; i < 4; i++) {
        int itemIdx = internalState.settingsMenuScrollOffset + i;
        if (itemIdx >= settingsMenuOptionsSize) break; // Если пунктов меньше 4, выходим раньше

        bool isSel = (itemIdx == internalState.settingsMenuSelectedIndex);
        int yPos = 32 + (i * 20); // i от 0 до 3 (позиция на экране)

        displaySprite.fillRect(20, yPos, 200, 18, isSel ? UI_ACCENT : UI_BG);
        displaySprite.drawString(settingsMenuOptions[itemIdx].label, SCREEN_WIDTH / 2, yPos + 9, &fonts::Font2);
    }
}

void renderBrightnessSetupScreen() {
    displaySprite.fillSprite(UI_BG);
    drawHeader("BRIGHTNESS SETUP");
    drawProgressBar((float)internalState.brightnessSetupBrightnessCounter / 255.0f, UI_VALID);
    drawFooter({"[Esc]: Back  [Arrows]: Led [Enter]: Set"});

    // Обводка палитры
    int w = SCREEN_WIDTH;
    int h = 66;
    int x = 0;
    int y = 31;
    displaySprite.drawRect(x, y, w, h, UI_FG);

    uint16_t testColors[] = {
        UI_FG,
        UI_ACCENT,
        UI_VALID,
        UI_DANGER,
        UI_MUTED,
        UI_BG,
    };

    int numCols = 6;
    int numRows = 2;
    int innerW = w - 2;
    int innerH = h - 2;
    int rowH = innerH / numRows;

    for (int row = 0; row < numRows; row++) {
        for (int col = 0; col < numCols; col++) {
            // Расчет горизонтальных границ внутри рамки
            int x1 = (col * innerW) / numCols;
            int x2 = ((col + 1) * innerW) / numCols;
            int currentBarW = x2 - x1;

            // Смещение индекса для шахматного порядка
            int colorIndex = (col + (row * 3)) % 6;

            // Позиция Y с учетом отступа от рамки (+1)
            int currY = y + 1 + (row * rowH);

            // Рисуем цветной блок
            // x + 1 — это отступ от левого края рамки
            displaySprite.fillRect(x + 1 + x1, currY, currentBarW, rowH, testColors[colorIndex]);
        }
    }
}

void renderVolumeSetupScreen() {
    displaySprite.fillSprite(UI_BG);
    drawHeader("VOLUME SETUP");
    drawProgressBar((float)internalState.volumeSetupVolumeCounter / 255.0f, UI_DANGER);
    drawFooter({"[Esc]: Back  [Arrows]: Vol [Enter]: Set"});

    // Обводка графика
    int w = SCREEN_WIDTH;
    int h = 66;
    int x = 0;
    int y = 31;
    displaySprite.drawRect(x, y, w, h, UI_FG);

    // График
    int numBars = 30;
    float barStep = (float)(w - 4) / numBars;
    int barGap = 2;
    int barW = (int)barStep - barGap;
    float volMultiplier = internalState.volumeSetupVolumeCounter / 255.0f;
    for (int i = 0; i < numBars; i++) {
        float noise = (sin(millis() / 150.0f + i * 0.8f) + 1.0f) / 2.0f;
        int maxH = h - 6;
        int barH = (int)(maxH * volMultiplier * noise);

        if (internalState.volumeSetupVolumeCounter > 0 && barH < 2) barH = 2;

        int bx = x + 2 + (int)(i * barStep);
        int by = y + h - barH - 2;

        // Столбик
        displaySprite.fillRect(bx, by, barW, barH, UI_DANGER);

        // Пик
        displaySprite.fillRect(bx, by - 2, barW, 1, UI_FG);
    }
}

void renderSoundSetupScreen() {
    const char *kbdModes[] = {"OFF", "SIMPLE", "MORSE"};
    const char *totpModes[] = {"OFF", "SIMPLE", "MORSE"};
    String fields[4] = {
        "X-Screen: < " + String(internalState.soundSetupExternalState ? "ON" : "OFF") + " >",
        "Keyboard: < " + String(kbdModes[internalState.soundSetupKeyboard]) + " >",
        "TOTP: < " + String(totpModes[internalState.soundSetupTOTP]) + " >",
        "Screenshot: < " + String(internalState.soundSetupScreenshot ? "ON" : "OFF") + " >",
    };

    displaySprite.fillSprite(UI_BG);
    drawHeader("SOUND SETUP");
    drawFooter({"   [Tab]: Switch    [Arrows]: Change", "   [Esc]: Cancel    [Enter]: Confirm"});

    displaySprite.setTextDatum(top_left);
    displaySprite.setFont(&fonts::Font2);

    for (int i = 0; i < 4; i++) {
        displaySprite.setTextColor(internalState.soundSetupFieldIdx == i ? UI_VALID : UI_FG);
        displaySprite.drawString(fields[i], 10, 34 + (i * 15));
    }
}

void renderChangePasswordScreen() {
    const int charWidth = 24;
    const int maxCharsPerLine = 10;
    const int linesPerPage = 2;

    // Подготовка отображаемого текста
    String rawDisplay = internalState.changePasswordInput;
    if (!internalState.changePasswordShowPassword) {
        rawDisplay = "";
        for (int i = 0; i < (int)internalState.changePasswordInput.length(); i++) rawDisplay += "*";
    }

    // Нарезка на строки
    std::vector<String> lines;
    if (rawDisplay.length() == 0) lines.push_back("");
    else {
        for (int i = 0; i < (int)rawDisplay.length(); i += maxCharsPerLine) {
            lines.push_back(rawDisplay.substring(i, min(i + maxCharsPerLine, (int)rawDisplay.length())));
        }
        // Если курсор на новой строке
        if (internalState.changePasswordCursorPosition > 0 && internalState.changePasswordCursorPosition % maxCharsPerLine == 0 && internalState.changePasswordCursorPosition == (int)internalState.changePasswordInput.length()) {
            lines.push_back("");
        }
    }

    // Авто-скролл
    int cursorLineIdx = internalState.changePasswordCursorPosition / maxCharsPerLine;
    if (cursorLineIdx < internalState.changePasswordScrollOffset) internalState.changePasswordScrollOffset = cursorLineIdx;
    if (cursorLineIdx >= internalState.changePasswordScrollOffset + linesPerPage) internalState.changePasswordScrollOffset = cursorLineIdx - (linesPerPage - 1);

    displaySprite.fillSprite(UI_BG);
    drawHeader("CHANGE PASSWORD");
    drawFooter({" [Tab]: Show/Hide  [FN+Arrows]: Cursor", " [FN+Esc]: Back    [Enter]: Confirm"});

    displaySprite.setTextColor(UI_VALID);
    displaySprite.setTextDatum(middle_center);

    // Вычисляем стартовую X-координату для центрирования всего БЛОКА (10 символов)
    int startX = (SCREEN_WIDTH - maxCharsPerLine * charWidth) / 2 + (charWidth / 2);
    for (int i = 0; i < linesPerPage; i++) {
        int lineIdx = internalState.changePasswordScrollOffset + i;

        // Фиксированная Y-координата
        int yPos = (SCREEN_HEIGHT / 2 - 18) + (i * 36);

        // Отрисовка текста
        if (lineIdx < (int)lines.size()) {
            String txt = lines[lineIdx];
            for (int j = 0; j < (int)txt.length(); j++) {
                displaySprite.drawString(String(txt[j]), startX + (j * charWidth), yPos, &fonts::Font4);
            }
        }

        // Отрисовка курсора
        if ((millis() % 1000) < 400 && lineIdx == cursorLineIdx) {
            int cursorXInLine = internalState.changePasswordCursorPosition % maxCharsPerLine;

            // Сдвигаем курсор на левый край текущей ячейки символа
            int cursorX = startX + (cursorXInLine * charWidth) - (charWidth / 2);

            // Рисуем курсор
            displaySprite.fillRect(cursorX, yPos - 12, 2, 24, UI_ACCENT);
        }
    }
}

void renderAccountListScreen() {
    time_t localTime = time(NULL) + (internalState.timeSetupUTCOffsetInput * 3600);
    struct tm *t = gmtime(&localTime);
    char timeStr[24];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", t);

    displaySprite.fillSprite(UI_BG);
    drawHeader(timeStr);
    drawScrollbar(internalState.accountListScrollOffset, 4, savedAccounts.size() + 1, 28, 88);
    drawFooter({"   [Esc]: Settings  [Enter]: Actions"});

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_left);

    for (int i = 0; i < 4; i++) {
        int idx = internalState.accountListScrollOffset + i;
        int yPos = 28 + (i * 22);
        if (idx <= (int)savedAccounts.size()) {
            bool isSel = (idx == internalState.accountListSelectedIndex);
            displaySprite.fillRect(4, yPos, SCREEN_WIDTH - 12, 20, isSel ? UI_ACCENT : UI_BG);

            String txt = (idx == 0) ? "[Enter]: Add new account" : savedAccounts[idx - 1].name;
            displaySprite.drawString(txt, 12, yPos + 10, &fonts::Font2);
        }
    }
}

void renderAddEditAccountScreen() {
    const char *algos[] = {"SHA1", "SHA256", "SHA512"};
    String fields[5] = {
        "Name: " + internalState.addEditAccountNameInput,
        "Key: " + internalState.addEditAccountKeyInput,
        "Algo: < " + String(algos[internalState.addEditAccountAlgoInput]) + " >",
        "Digits: < " + String(internalState.addEditAccountDigitsInput) + " >",
        "Period: < " + String(internalState.addEditAccountPeriodInput) + "s >",
    };

    displaySprite.fillSprite(UI_BG);
    drawHeader(internalState.isEditMode ? "EDIT ACCOUNT" : "ADD ACCOUNT");
    drawFooter({"   [Tab]: Switch    [Arrows]: Change", "   [Esc]: Cancel    [Enter]: Confirm"});

    displaySprite.setTextDatum(top_left);
    displaySprite.setFont(&fonts::Font2);

    for (int i = 0; i < 5; i++) {
        displaySprite.setTextColor(internalState.addEditAccountFieldIdx == i ? UI_VALID : UI_FG);
        displaySprite.drawString(fields[i], 10, 26 + (i * 15));
    }
}

void renderActionMenuScreen() {
    displaySprite.fillSprite(UI_BG);
    drawHeader(savedAccounts[internalState.accountListSelectedIndex - 1].name);
    drawScrollbar(internalState.actionMenuScrollOffset, 4, actionMenuOptionsSize, 32, 4 * 20);
    drawFooter({"   [Esc]: Back       [Enter]: Select"});

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_center);

    for (int i = 0; i < 4; i++) {
        int itemIdx = internalState.actionMenuScrollOffset + i;
        if (itemIdx >= actionMenuOptionsSize) break; // Если пунктов меньше 4, выходим раньше

        bool isSel = (itemIdx == internalState.actionMenuSelectedIndex);
        int yPos = 32 + (i * 20); // i от 0 до 3 (позиция на экране)

        displaySprite.fillRect(20, yPos, 200, 18, isSel ? UI_ACCENT : UI_BG);
        displaySprite.drawString(actionMenuOptions[itemIdx].label, SCREEN_WIDTH / 2, yPos + 9, &fonts::Font2);
    }
}

void renderViewTotpScreen() {
    time_t now = time(NULL);
    Account acc = savedAccounts[internalState.accountListSelectedIndex - 1];
    String code = generateTOTP(acc.key, acc.algo, acc.digits, acc.period, now);

    displaySprite.fillSprite(UI_BG);
    drawHeader(acc.name);
    drawFooter({"   [Esc]: Back [Enter]: Type via USB"});

    displaySprite.setTextDatum(middle_center);

    if (code == "ERROR") {
        displaySprite.setTextColor(UI_DANGER);
        displaySprite.drawString("BAD KEY", SCREEN_WIDTH / 2, 74, &fonts::Font6);
    } else {
        displaySprite.setTextColor(UI_VALID);
        displaySprite.drawString(acc.digits == 8 ? code.substring(0, 4) + " " + code.substring(4) : code.substring(0, 3) + " " + code.substring(3), SCREEN_WIDTH / 2, 74, &fonts::Font6);
    }

    int secondsLeft = acc.period - (now % acc.period);
    drawProgressBar((float)secondsLeft / acc.period, (code == "ERROR") ? UI_MUTED : ((secondsLeft < 5) ? UI_DANGER : UI_VALID));
}

void renderViewQrScreen() {
    Account acc = savedAccounts[internalState.accountListSelectedIndex - 1];
    const char *algos[] = {"SHA1", "SHA256", "SHA512"};
    String uri = "otpauth://totp/" + urlEncode(acc.name) + "?secret=" + acc.key + "&algorithm=" + algos[acc.algo] + "&digits=" + String(acc.digits) + "&period=" + String(acc.period);

    QRCode qrcode;
    uint8_t qrcodeData[qrcode_getBufferSize(10)];
    qrcode_initText(&qrcode, qrcodeData, 10, 0, uri.c_str());

    int scale = (qrcode.size < 35) ? 3 : 2;
    int size = qrcode.size * scale;
    int offsetX = 10, offsetY = (SCREEN_HEIGHT - size) / 2;
    int txtX = offsetX + size + ((SCREEN_WIDTH - (offsetX + size)) / 2);

    displaySprite.fillSprite(WHITE);
    for (uint8_t y = 0; y < qrcode.size; y++) {
        for (uint8_t x = 0; x < qrcode.size; x++) {
            if (qrcode_getModule(&qrcode, x, y)) {
                displaySprite.fillRect(offsetX + x * scale, offsetY + y * scale, scale, scale, BLACK);
            }
        }
    }

    displaySprite.setTextColor(BLACK);
    displaySprite.setTextDatum(middle_center);
    displaySprite.drawString("PRIVATE!", txtX, 40, &fonts::Font2);
    displaySprite.drawString("DO NOT", txtX, 60, &fonts::Font2);
    displaySprite.drawString("SHARE", txtX, 75, &fonts::Font2);

    displaySprite.setTextDatum(bottom_center);
    displaySprite.drawString("[Esc]: Back", txtX, 125, &fonts::Font0);
}

void renderDeleteAccountScreen() {
    displaySprite.fillSprite(UI_BG);
    drawHeader("DELETE ACCOUNT");
    drawFooter({"   [Esc]: Cancel    [Enter]: Confirm"});

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_center);
    displaySprite.drawString(savedAccounts[internalState.accountListSelectedIndex - 1].name, SCREEN_WIDTH / 2, 60, &fonts::Font4);

    displaySprite.setTextColor(UI_DANGER);
    displaySprite.drawString("This action is permanent.", SCREEN_WIDTH / 2, 90, &fonts::Font2);
}

// --- ОБРАБОТЧИКИ ЭКРАНОВ ---
void handleSplashInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Any key
    if (isChange) {
        switchExternalState(kState.enter ? STATE_LOGIN : STATE_GUIDE);
    }
}

void handleGuideInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        if (!internalState.isLoggedIn) {
            // Если ещё не вошли — на экран логина
            switchExternalState(STATE_LOGIN);
        } else if (!internalState.initialTimeSetupDone) {
            // Если вошли, но время не настроено — на установку времени
            switchExternalState(STATE_TIME_SETUP);
        } else {
            // Если всё пройдено — в меню настроек
            switchExternalState(STATE_SETTINGS_MENU);
        }
        return;
    }

    // Расчет вертикального максимума
    int fontHeight = 18; // Высота символа Font0
    int maxScrollY = max(0, userGuideLinesSize * fontHeight - 85);

    // Расчет горизонтального максимума
    size_t maxChars = 0;
    for (const String &line : userGuideLines)
        if (line.length() > maxChars) maxChars = line.length();

    int fontWidth = 10; // Ширина символа Font0
    // Вычисляем ширину самой длинной строки минус ширина экрана с учетом полей
    int maxScrollX = max(0, (int)(maxChars * fontWidth) - (SCREEN_WIDTH - 20));

    int step = 10;
    // Up
    if (kChar == ';') internalState.guideScrollY = max(0, internalState.guideScrollY - step);
    // Down
    else if (kChar == '.') internalState.guideScrollY = min(maxScrollY, internalState.guideScrollY + step);
    // Left
    else if (kChar == ',') internalState.guideScrollX = max(0, internalState.guideScrollX - step);
    // Right
    else if (kChar == '/') internalState.guideScrollX = min(maxScrollX, internalState.guideScrollX + step);

    internalState.requiresRedraw = true;
}

void handleLoginInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    if (internalState.loginErrorClearTime > 0) return;

    int &pos = internalState.loginCursorPosition;
    int len = internalState.loginPasswordInput.length();

    // Сбрасываем фазу мигания курсора при любом действии, чтобы он не исчезал во время печати
    internalState.requiresRedraw = true;

    // Fn+Esc
    if (isChange && kState.fn && kChar == '`') {
        switchExternalState(STATE_GUIDE);
        return;
    }
    // Fn+Up
    if (kState.fn && kChar == ';') {
        pos = max(0, pos - 10);
        return;
    }
    // Fn+Down
    if (kState.fn && kChar == '.') {
        pos = min(len, pos + 10);
        return;
    }
    // Fn+Left
    if (kState.fn && kChar == ',') {
        if (pos > 0) pos--;
        return;
    }
    // Fn+Right
    if (kState.fn && kChar == '/') {
        if (pos < len) pos++;
        return;
    }
    // Tab
    if (isChange && kState.tab) {
        internalState.loginShowPassword = !internalState.loginShowPassword;
        return;
    }
    if (kState.del) {
        // Delete
        if (kState.fn) {
            if (pos < len) internalState.loginPasswordInput.remove(pos, 1);
        }
        // Backspace
        else {
            if (pos > 0) {
                internalState.loginPasswordInput.remove(pos - 1, 1);
                pos--;
            }
        }
        return;
    }
    // Any other key
    if (kChar >= 32 && kChar <= 126) {
        String left = internalState.loginPasswordInput.substring(0, pos);
        String right = internalState.loginPasswordInput.substring(pos);
        internalState.loginPasswordInput = left + kChar + right;
        pos++;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        // Проверка существания файла
        bool isNewVault = !SD.exists(DATA_FILE_PATH);

        if (isNewVault || loadAccountsFromStorage()) {
            // Если файла нет, создаем по умолчанию
            if (isNewVault) saveAccountsToStorage();

            internalState.isLoggedIn = true;
            switchExternalState(STATE_TIME_SETUP);
        } else {
            // Особое сообщение о неправильном пароле
            internalState.loginErrorClearTime = millis();
        }
        return;
    }
}

void handleTimeSetupInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        if (internalState.initialTimeSetupDone) switchExternalState(STATE_SETTINGS_MENU);
        else switchExternalState(STATE_GUIDE);
        return;
    }
    // Any digit key
    if (isdigit(kChar)) {
        if (internalState.timeSetupTimeInput.length() < 14 && isNextDateTimeDigitValid(internalState.timeSetupTimeInput, kChar)) {
            internalState.timeSetupTimeInput += kChar;
            internalState.requiresRedraw = true;
        }
        return;
    }
    // Backspace
    if (kState.del) {
        if (internalState.timeSetupTimeInput.length() > 0) {
            internalState.timeSetupTimeInput.remove(internalState.timeSetupTimeInput.length() - 1);
            internalState.requiresRedraw = true;
        }
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',') {
        internalState.timeSetupUTCOffsetInput = min(14, internalState.timeSetupUTCOffsetInput + 1);
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/') {
        internalState.timeSetupUTCOffsetInput = max(-12, internalState.timeSetupUTCOffsetInput - 1);
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter && internalState.timeSetupTimeInput.length() == 14) {
        systemPreferences.putString("TA/time", internalState.timeSetupTimeInput);
        systemPreferences.putInt("TA/utc", internalState.timeSetupUTCOffsetInput);

        setenv("TZ", "UTC0", 1);
        tzset();
        struct tm t = {0};
        t.tm_year = internalState.timeSetupTimeInput.substring(0, 4).toInt() - 1900;
        t.tm_mon = internalState.timeSetupTimeInput.substring(4, 6).toInt() - 1;
        t.tm_mday = internalState.timeSetupTimeInput.substring(6, 8).toInt();
        t.tm_hour = internalState.timeSetupTimeInput.substring(8, 10).toInt();
        t.tm_min = internalState.timeSetupTimeInput.substring(10, 12).toInt();
        t.tm_sec = internalState.timeSetupTimeInput.substring(12, 14).toInt();
        t.tm_isdst = -1;

        time_t epoch = mktime(&t) - (internalState.timeSetupUTCOffsetInput * 3600);
        timeval tv = {.tv_sec = epoch};
        settimeofday(&tv, NULL);

        char tzBuffer[20];
        sprintf(tzBuffer, "GMT%s%d", (internalState.timeSetupUTCOffsetInput >= 0 ? "-" : "+"), abs(internalState.timeSetupUTCOffsetInput));
        setenv("TZ", tzBuffer, 1);
        tzset();

        if (internalState.initialTimeSetupDone) switchExternalState(STATE_SETTINGS_MENU);
        else switchExternalState(STATE_ACCOUNT_LIST);

        internalState.initialTimeSetupDone = true;
        return;
    }
}

void handleSettingsMenuInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        switchExternalState(STATE_GUIDE);
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',') {
        if (internalState.settingsMenuSelectedIndex > 0) {
            internalState.settingsMenuSelectedIndex--;
        } else {
            // Прыжок с первого на последний
            internalState.settingsMenuSelectedIndex = settingsMenuOptionsSize - 1;
        }

        // Корректировка скролла в видимой области (4 пункта)
        if (internalState.settingsMenuSelectedIndex < internalState.settingsMenuScrollOffset) {
            // Обычный скролл вверх
            internalState.settingsMenuScrollOffset = internalState.settingsMenuSelectedIndex;
        } else if (internalState.settingsMenuSelectedIndex >= internalState.settingsMenuScrollOffset + 4) {
            // Если перепрыгнули в самый конец, показываем последние 4 элемента
            int newOffset = settingsMenuOptionsSize - 4;
            internalState.settingsMenuScrollOffset = (newOffset > 0) ? newOffset : 0;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/') {
        if (internalState.settingsMenuSelectedIndex < settingsMenuOptionsSize - 1) {
            internalState.settingsMenuSelectedIndex++;
        } else {
            // Прыжок с последнего на первый
            internalState.settingsMenuSelectedIndex = 0;
        }

        // Корректировка скролла в видимой области (4 пункта)
        if (internalState.settingsMenuSelectedIndex >= internalState.settingsMenuScrollOffset + 4) {
            // Обычный скролл вниз
            internalState.settingsMenuScrollOffset = internalState.settingsMenuSelectedIndex - 3;
        } else if (internalState.settingsMenuSelectedIndex < internalState.settingsMenuScrollOffset) {
            // Если перепрыгнули в самое начало, сбрасываем смещение
            internalState.settingsMenuScrollOffset = 0;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter && internalState.timeSetupTimeInput.length() == 14) {
        settingsMenuOptions[internalState.settingsMenuSelectedIndex].action();
        return;
    }
}

void handleBrightnessSetupInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        internalState.brightnessSetupBrightnessCounter = systemPreferences.getInt("TA/brght", DEFAULT_BRIGHTNESS);
        M5.Display.setBrightness(internalState.brightnessSetupBrightnessCounter);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
    // Up or Right
    if (kChar == ';' || kChar == '/') {
        internalState.brightnessSetupBrightnessCounter = min(255, internalState.brightnessSetupBrightnessCounter + 5);
        M5.Display.setBrightness(internalState.brightnessSetupBrightnessCounter); // Предпросмотр
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Left
    if (kChar == '.' || kChar == ',') {
        internalState.brightnessSetupBrightnessCounter = max(0, internalState.brightnessSetupBrightnessCounter - 5);
        M5.Display.setBrightness(internalState.brightnessSetupBrightnessCounter); // Предпросмотр
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        systemPreferences.putInt("TA/brght", internalState.brightnessSetupBrightnessCounter);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
}

void handleVolumeSetupInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        internalState.volumeSetupVolumeCounter = systemPreferences.getInt("TA/vol", DEFAULT_VOLUME);
        M5.Speaker.setVolume(internalState.volumeSetupVolumeCounter);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
    // Up or Right
    if (kChar == ';' || kChar == '/') {
        internalState.volumeSetupVolumeCounter = min(255, internalState.volumeSetupVolumeCounter + 5);
        M5.Speaker.setVolume(internalState.volumeSetupVolumeCounter); // Предпросмотр

        // Тестовый звук
        if (internalState.volumeSetupVolumeCounter > 0) {
            // Восходящий звук
            M5.Speaker.tone(880, 60);
            delay(30);
            M5.Speaker.tone(1200, 60);
        }

        internalState.requiresRedraw = true;
        return;
    }
    // Down or Left
    if (kChar == '.' || kChar == ',') {
        internalState.volumeSetupVolumeCounter = max(0, internalState.volumeSetupVolumeCounter - 5);
        M5.Speaker.setVolume(internalState.volumeSetupVolumeCounter); // Предпросмотр

        // Тестовый звук
        if (internalState.volumeSetupVolumeCounter > 0) {
            // Нисходящий звук
            M5.Speaker.tone(1200, 60);
            delay(30);
            M5.Speaker.tone(880, 60);
        }

        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        systemPreferences.putInt("TA/vol", internalState.volumeSetupVolumeCounter);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
}

void handleSoundSetupInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        internalState.soundSetupExternalState = systemPreferences.getBool("TA/snd_es", DEFAULT_SOUND_ES);
        internalState.soundSetupKeyboard = systemPreferences.getInt("TA/snd_kbd", DEFAULT_SOUND_KBD);
        internalState.soundSetupTOTP = systemPreferences.getInt("TA/snd_totp", DEFAULT_SOUND_TOTP);
        internalState.soundSetupScreenshot = systemPreferences.getBool("TA/snd_scr", DEFAULT_SOUND_SCR);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
    // Tab
    if (kState.tab) {
        internalState.soundSetupFieldIdx = (internalState.soundSetupFieldIdx + 1) % 4;
        internalState.requiresRedraw = true;
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',') {
        switch (internalState.soundSetupFieldIdx) {
        case 0: // Переходы
            internalState.soundSetupExternalState = !internalState.soundSetupExternalState;
            break;
        case 1: // Клавиатура (назад: 0->2, 2->1, 1->0)
            internalState.soundSetupKeyboard = (internalState.soundSetupKeyboard + 2) % 3;
            break;
        case 2: // TOTP (назад: 0->2, 2->1, 1->0)
            internalState.soundSetupTOTP = (internalState.soundSetupTOTP + 2) % 3;
            break;
        case 3: // Скриншот
            internalState.soundSetupScreenshot = !internalState.soundSetupScreenshot;
            break;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/') {
        switch (internalState.soundSetupFieldIdx) {
        case 0: // Переходы
            internalState.soundSetupExternalState = !internalState.soundSetupExternalState;
            break;
        case 1: // Клавиатура (вперед: 0->1, 1->2, 2->0)
            internalState.soundSetupKeyboard = (internalState.soundSetupKeyboard + 1) % 3;
            break;
        case 2: // Клавиатура (вперед: 0->1, 1->2, 2->0)
            internalState.soundSetupTOTP = (internalState.soundSetupTOTP + 1) % 3;
            break;
        case 3: // Скриншот
            internalState.soundSetupScreenshot = !internalState.soundSetupScreenshot;
            break;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        systemPreferences.putBool("TA/snd_es", internalState.soundSetupExternalState);
        systemPreferences.putInt("TA/snd_kbd", internalState.soundSetupKeyboard);
        systemPreferences.putInt("TA/snd_totp", internalState.soundSetupTOTP);
        systemPreferences.putBool("TA/snd_scr", internalState.soundSetupScreenshot);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
}

void handleChangePasswordInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    int &pos = internalState.changePasswordCursorPosition;
    int len = internalState.changePasswordInput.length();

    // Сбрасываем фазу мигания курсора при любом действии, чтобы он не исчезал во время печати
    internalState.requiresRedraw = true;

    // Fn+Esc
    if (isChange && kState.fn && kChar == '`') {
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
    // Fn+Up
    if (kState.fn && kChar == ';') {
        pos = max(0, pos - 10);
        return;
    }
    // Fn+Down
    if (kState.fn && kChar == '.') {
        pos = min(len, pos + 10);
        return;
    }
    // Fn+Left
    if (kState.fn && kChar == ',') {
        if (pos > 0) pos--;
        return;
    }
    // Fn+Right
    if (kState.fn && kChar == '/') {
        if (pos < len) pos++;
        return;
    }
    // Tab
    if (isChange && kState.tab) {
        internalState.changePasswordShowPassword = !internalState.changePasswordShowPassword;
        return;
    }
    if (kState.del) {
        // Delete
        if (kState.fn) {
            if (pos < len) internalState.changePasswordInput.remove(pos, 1);
        }
        // Backspace
        else {
            if (pos > 0) {
                internalState.changePasswordInput.remove(pos - 1, 1);
                pos--;
            }
        }
        return;
    }
    // Any other key
    if (kChar >= 32 && kChar <= 126) {
        String left = internalState.changePasswordInput.substring(0, pos);
        String right = internalState.changePasswordInput.substring(pos);
        internalState.changePasswordInput = left + kChar + right;
        pos++;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        performPasswordChange();

        drawMessage({"PASSWORD", "CHANGED"});
        delay(600);

        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
}

void handleAccountListInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',') {
        internalState.accountListSelectedIndex = (internalState.accountListSelectedIndex > 0) ? internalState.accountListSelectedIndex - 1 : savedAccounts.size();
        if (internalState.accountListSelectedIndex < internalState.accountListScrollOffset) internalState.accountListScrollOffset = internalState.accountListSelectedIndex;
        if (internalState.accountListSelectedIndex == (int)savedAccounts.size()) internalState.accountListScrollOffset = max(0, (int)savedAccounts.size() - 3);
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/') {
        internalState.accountListSelectedIndex++;
        if (internalState.accountListSelectedIndex > (int)savedAccounts.size()) {
            internalState.accountListSelectedIndex = 0;
            internalState.accountListScrollOffset = 0;
        }
        if (internalState.accountListSelectedIndex >= internalState.accountListScrollOffset + 4) internalState.accountListScrollOffset++;
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        if (internalState.accountListSelectedIndex == 0) {
            internalState.isEditMode = false;
            switchExternalState(STATE_ADD_EDIT_ACCOUNT);
        } else {
            switchExternalState(STATE_ACTION_MENU);
        }
        return;
    }
}

void handleActionMenuInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        switchExternalState(STATE_ACCOUNT_LIST);
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',') {
        if (internalState.actionMenuSelectedIndex > 0) {
            internalState.actionMenuSelectedIndex--;
        } else {
            // Прыжок с первого на последний
            internalState.actionMenuSelectedIndex = actionMenuOptionsSize - 1;
        }

        // Корректировка скролла в видимой области (4 пункта)
        if (internalState.actionMenuSelectedIndex < internalState.actionMenuScrollOffset) {
            // Обычный скролл вверх
            internalState.actionMenuScrollOffset = internalState.actionMenuSelectedIndex;
        } else if (internalState.actionMenuSelectedIndex >= internalState.actionMenuScrollOffset + 4) {
            // Если перепрыгнули в самый конец, показываем последние 4 элемента
            int newOffset = actionMenuOptionsSize - 4;
            internalState.actionMenuScrollOffset = (newOffset > 0) ? newOffset : 0;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/') {
        if (internalState.actionMenuSelectedIndex < actionMenuOptionsSize - 1) {
            internalState.actionMenuSelectedIndex++;
        } else {
            // Прыжок с последнего на первый
            internalState.actionMenuSelectedIndex = 0;
        }

        // Корректировка скролла в видимой области (4 пункта)
        if (internalState.actionMenuSelectedIndex >= internalState.actionMenuScrollOffset + 4) {
            // Обычный скролл вниз
            internalState.actionMenuScrollOffset = internalState.actionMenuSelectedIndex - 3;
        } else if (internalState.actionMenuSelectedIndex < internalState.actionMenuScrollOffset) {
            // Если перепрыгнули в самое начало, сбрасываем смещение
            internalState.actionMenuScrollOffset = 0;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        actionMenuOptions[internalState.actionMenuSelectedIndex].action();
        return;
    }
}

void handleAddEditAccountInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        if (internalState.isEditMode) {
            internalState.addEditAccountFieldIdx = 0;
            internalState.addEditAccountNameInput = "";
            internalState.addEditAccountKeyInput = "";
            internalState.addEditAccountAlgoInput = 0;
            internalState.addEditAccountDigitsInput = 6;
            internalState.addEditAccountPeriodInput = 30;
            switchExternalState(STATE_ACTION_MENU);
        } else switchExternalState(STATE_ACCOUNT_LIST);
        return;
    }
    // Tab
    if (kState.tab) {
        internalState.addEditAccountFieldIdx = (internalState.addEditAccountFieldIdx + 1) % 5;
        internalState.requiresRedraw = true;
        return;
    }

    if (internalState.addEditAccountFieldIdx < 2) {
        // Delete
        if (kState.del) {
            if (internalState.addEditAccountFieldIdx == 0 && internalState.addEditAccountNameInput.length() > 0) {
                internalState.addEditAccountNameInput.remove(internalState.addEditAccountNameInput.length() - 1);
            } else if (internalState.addEditAccountFieldIdx == 1 && internalState.addEditAccountKeyInput.length() > 0) {
                internalState.addEditAccountKeyInput.remove(internalState.addEditAccountKeyInput.length() - 1);
            }
            internalState.requiresRedraw = true;
            return;
        }
        // Any other key
        if (kChar >= 32 && kChar <= 126) {
            if (internalState.addEditAccountFieldIdx == 0 && internalState.addEditAccountNameInput.length() < MAX_ACCOUNT_NAME_LENGTH) {
                internalState.addEditAccountNameInput += kChar;
            } else if (internalState.addEditAccountFieldIdx == 1 && internalState.addEditAccountKeyInput.length() < MAX_BASE32_DECODE_LENGTH) {
                char c = toupper(kChar);
                if ((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) internalState.addEditAccountKeyInput += c;
            }
            internalState.requiresRedraw = true;
            return;
        }
    } else {
        // Up or Left
        if (kChar == ';' || kChar == ',') {
            if (internalState.addEditAccountFieldIdx == 2) internalState.addEditAccountAlgoInput = (internalState.addEditAccountAlgoInput + 2) % 3;
            if (internalState.addEditAccountFieldIdx == 3) internalState.addEditAccountDigitsInput = (internalState.addEditAccountDigitsInput == 6) ? 8 : 6;
            if (internalState.addEditAccountFieldIdx == 4) internalState.addEditAccountPeriodInput = (internalState.addEditAccountPeriodInput == 30) ? 60 : 30;
            internalState.requiresRedraw = true;
            return;
        }
        // Down or Right
        if (kChar == '.' || kChar == '/') {
            if (internalState.addEditAccountFieldIdx == 2) internalState.addEditAccountAlgoInput = (internalState.addEditAccountAlgoInput + 1) % 3;
            if (internalState.addEditAccountFieldIdx == 3) internalState.addEditAccountDigitsInput = (internalState.addEditAccountDigitsInput == 6) ? 8 : 6;
            if (internalState.addEditAccountFieldIdx == 4) internalState.addEditAccountPeriodInput = (internalState.addEditAccountPeriodInput == 30) ? 60 : 30;
            internalState.requiresRedraw = true;
            return;
        }
    }
    // Enter
    if (isChange && kState.enter) {
        internalState.addEditAccountNameInput.trim();
        internalState.addEditAccountKeyInput.trim();
        if (internalState.addEditAccountNameInput.length() > 0 && internalState.addEditAccountKeyInput.length() > 0) {
            Account newAcc = {
                internalState.addEditAccountNameInput,
                internalState.addEditAccountKeyInput,
                internalState.addEditAccountAlgoInput,
                internalState.addEditAccountDigitsInput,
                internalState.addEditAccountPeriodInput};
            if (internalState.isEditMode) savedAccounts[internalState.accountListSelectedIndex - 1] = newAcc;
            else savedAccounts.push_back(newAcc);
            saveAccountsToStorage();

            drawMessage({"ACCOUNT", "SAVED"});
            delay(400);

            internalState.addEditAccountFieldIdx = 0;
            internalState.addEditAccountNameInput = "";
            internalState.addEditAccountKeyInput = "";
            internalState.addEditAccountAlgoInput = 0;
            internalState.addEditAccountDigitsInput = 6;
            internalState.addEditAccountPeriodInput = 30;
            switchExternalState(internalState.isEditMode ? STATE_ACTION_MENU : STATE_ACCOUNT_LIST);
        }
        return;
    }
}

void handleDeleteAccountInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        switchExternalState(STATE_ACTION_MENU);
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        int deletedIndex = internalState.accountListSelectedIndex;
        savedAccounts.erase(savedAccounts.begin() + (deletedIndex - 1));
        saveAccountsToStorage();

        drawMessage({"ACCOUNT", "DELETED"});
        delay(400);

        // Смещение индекса на предыдущий элемент списка
        internalState.accountListSelectedIndex = max(0, deletedIndex - 1);
        switchExternalState(STATE_ACCOUNT_LIST);
    }
}

void handleViewTotpInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        switchExternalState(STATE_ACTION_MENU);
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        Account acc = savedAccounts[internalState.accountListSelectedIndex - 1];
        String code = generateTOTP(acc.key, acc.algo, acc.digits, acc.period, time(NULL));

        drawMessage({"TYPING", "VIA USB"});
        switch (internalState.soundSetupTOTP) {
        case 0:
            delay(300);
            break;
        case 1:
            if (internalState.volumeSetupVolumeCounter > 0) {
                M5.Speaker.tone(1500, 40);
                delay(50);
                M5.Speaker.tone(1800, 40);
                delay(50);
                M5.Speaker.tone(2000, 100);
                delay(200);
            }
            break;
        case 2:
            playMorseTOTPCode(code);
            break;
        }

        for (char c : code) {
            usbKeyboard.write(c);
            delay(15);
        }

        internalState.requiresRedraw = true;
    }
}

void handleViewQrInput(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') switchExternalState(STATE_ACTION_MENU);
}

// --- ГЛАВНЫЙ ОБРАБОТЧИК КЛАВИАТУРЫ ---
void processKeyboardEvents() {
    // Если нажатая клавиша изменилась
    bool isChange = M5Cardputer.Keyboard.isChange();
    // Если нажата любая клавиша
    bool isPressed = M5Cardputer.Keyboard.isPressed();

    if (!isPressed) return; // Нет нажатия, нечего обрабатывать

    // Модификатор
    Keyboard_Class::KeysState kState = M5Cardputer.Keyboard.keysState();
    // Символ
    char kChar = kState.word.size() > 0 ? kState.word[0] : 0;

    // Динамическая задержка скролла
    int repeatDelay;
    switch (internalState.currentExternalState) {
    case STATE_SPLASH_SCREEN:
    case STATE_GUIDE:
        repeatDelay = 50;
        break;
    case STATE_BRIGHTNESS_SETUP:
    case STATE_VOLUME_SETUP:
        repeatDelay = 170;
        break;
    case STATE_LOGIN:
    case STATE_TIME_SETUP:
    case STATE_SETTINGS_MENU:
    case STATE_SOUND_SETUP:
    case STATE_CHANGE_PASSWORD:
    case STATE_ACCOUNT_LIST:
    case STATE_ACTION_MENU:
    case STATE_ADD_EDIT_ACCOUNT:
    case STATE_DELETE_ACCOUNT:
    case STATE_VIEW_TOTP:
    case STATE_VIEW_QR:
        repeatDelay = 250;
        break;
    }

    static ulong lastKeyPressTime = 0;
    if (isChange || (millis() - lastKeyPressTime > repeatDelay)) {
        lastKeyPressTime = millis();

        // Звуковая индикация
        switch (internalState.soundSetupKeyboard) {
        // Off
        case 0:
            break;
        // Simple
        case 1:
            playKeyTone(kChar, kState);
            break;
        // Morse
        case 2:
            playMorseTone(kChar, kState);
            break;
        }

        switch (internalState.currentExternalState) {
        case STATE_SPLASH_SCREEN:
            handleSplashInput(kState, kChar, isChange);
            break;
        case STATE_GUIDE:
            handleGuideInput(kState, kChar, isChange);
            break;
        case STATE_LOGIN:
            handleLoginInput(kState, kChar, isChange);
            break;
        case STATE_TIME_SETUP:
            handleTimeSetupInput(kState, kChar, isChange);
            break;
        case STATE_SETTINGS_MENU:
            handleSettingsMenuInput(kState, kChar, isChange);
            break;
        case STATE_BRIGHTNESS_SETUP:
            handleBrightnessSetupInput(kState, kChar, isChange);
            break;
        case STATE_VOLUME_SETUP:
            handleVolumeSetupInput(kState, kChar, isChange);
            break;
        case STATE_SOUND_SETUP:
            handleSoundSetupInput(kState, kChar, isChange);
            break;
        case STATE_CHANGE_PASSWORD:
            handleChangePasswordInput(kState, kChar, isChange);
            break;
        case STATE_ACCOUNT_LIST:
            handleAccountListInput(kState, kChar, isChange);
            break;
        case STATE_ACTION_MENU:
            handleActionMenuInput(kState, kChar, isChange);
            break;
        case STATE_ADD_EDIT_ACCOUNT:
            handleAddEditAccountInput(kState, kChar, isChange);
            break;
        case STATE_DELETE_ACCOUNT:
            handleDeleteAccountInput(kState, kChar, isChange);
            break;
        case STATE_VIEW_TOTP:
            handleViewTotpInput(kState, kChar, isChange);
            break;
        case STATE_VIEW_QR:
            handleViewQrInput(kState, kChar, isChange);
            break;
        }
    }
}

// --- ГЛАВНЫЙ ОТРИСОВЩИК ЭКРАНА ---
void renderUserInterface() {
    if (!internalState.requiresRedraw) return;
    displaySprite.clearClipRect();

    switch (internalState.currentExternalState) {
    case STATE_SPLASH_SCREEN:
        renderSplashScreen();
        break;
    case STATE_GUIDE:
        renderGuideScreen();
        break;
    case STATE_LOGIN:
        renderLoginScreen();
        break;
    case STATE_TIME_SETUP:
        renderTimeSetupScreen();
        break;
    case STATE_SETTINGS_MENU:
        renderSettingsMenuScreen();
        break;
    case STATE_BRIGHTNESS_SETUP:
        renderBrightnessSetupScreen();
        break;
    case STATE_VOLUME_SETUP:
        renderVolumeSetupScreen();
        break;
    case STATE_SOUND_SETUP:
        renderSoundSetupScreen();
        break;
    case STATE_CHANGE_PASSWORD:
        renderChangePasswordScreen();
        break;
    case STATE_ACCOUNT_LIST:
        renderAccountListScreen();
        break;
    case STATE_ACTION_MENU:
        renderActionMenuScreen();
        break;
    case STATE_ADD_EDIT_ACCOUNT:
        renderAddEditAccountScreen();
        break;
    case STATE_DELETE_ACCOUNT:
        renderDeleteAccountScreen();
        break;
    case STATE_VIEW_TOTP:
        renderViewTotpScreen();
        break;
    case STATE_VIEW_QR:
        renderViewQrScreen();
        break;
    }

    displaySprite.pushSprite(0, 0);
    internalState.requiresRedraw = false;
}

// --- ОБРАБОТЧИК СКРИНШОТОВ ---
void processScreenshotEvent() {
    if (!M5Cardputer.BtnA.isPressed()) return;

    static ulong lastScreenshotTime = 0;
    if (millis() - lastScreenshotTime < 1000) return;
    lastScreenshotTime = millis();

    ensureDirectoryExists(SCREENSHOTS_DIR_PATH);

    // Инициализация индекса (поиск максимума) при первом вызове
    static int nextFileIndex = 0;
    if (nextFileIndex == 0) {
        int maxIndex = 0;
        String dirPath = SCREENSHOTS_DIR_PATH;
        if (dirPath.endsWith("/")) dirPath.remove(dirPath.length() - 1);

        File scrDir = SD.open(dirPath);
        if (scrDir && scrDir.isDirectory()) {
            File scrFile = scrDir.openNextFile();
            while (scrFile) {
                // Используем полное имя файла из объекта File
                const char *fileName = scrFile.name();

                // Ищем "scr_" в имени
                const char *found = strstr(fileName, "scr_");
                if (found) {
                    // Смещаем указатель на длину строки "scr_"
                    // И берем число сразу после "scr_"
                    int idx = atoi(found + 4);
                    if (idx > maxIndex) maxIndex = idx;
                }
                scrFile.close();
                scrFile = scrDir.openNextFile();
            }
            scrDir.close();
        }
        nextFileIndex = maxIndex + 1;
    }

    // Формируем финальное имя и путь
    char fileName[32];
    char filePath[128];
    snprintf(fileName, sizeof(fileName), "scr_%04u.bmp", nextFileIndex);
    snprintf(filePath, sizeof(filePath), "%s%s", SCREENSHOTS_DIR_PATH, fileName);

    // Запись файла
    File file = SD.open(filePath, FILE_WRITE);
    if (!file) return;

    uint32_t fileSize = 54 + (SCREEN_WIDTH * SCREEN_HEIGHT * 3);
    uint8_t header[54] = {
        'B',
        'M',
        (uint8_t)(fileSize),
        (uint8_t)(fileSize >> 8),
        (uint8_t)(fileSize >> 16),
        (uint8_t)(fileSize >> 24),
        0,
        0,
        0,
        0,
        54,
        0,
        0,
        0,
        40,
        0,
        0,
        0,
        240,
        0,
        0,
        0,
        121,
        255,
        255,
        255,
        1,
        0,
        24,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };
    file.write(header, 54);

    uint8_t lineBuffer[SCREEN_WIDTH * 3];
    for (int y = 0; y < SCREEN_HEIGHT; y++) {
        int pos = 0;
        for (int x = 0; x < SCREEN_WIDTH; x++) {
            uint16_t color = displaySprite.readPixel(x, y);
            lineBuffer[pos++] = (color & 0x001F) << 3; // B
            lineBuffer[pos++] = (color & 0x07E0) >> 3; // G
            lineBuffer[pos++] = (color & 0xF800) >> 8; // R
        }
        file.write(lineBuffer, sizeof(lineBuffer));
    }
    file.close();

    // Инкремент для следующего файла
    nextFileIndex++;

    drawMessage({"SCREENSHOT", "SAVED", fileName});
    // Звуковая индикация
    if (internalState.volumeSetupVolumeCounter > 0 && internalState.soundSetupScreenshot) {
        M5.Speaker.tone(1000, 60);
        delay(40);
        M5.Speaker.tone(900, 60);
        delay(40);
        M5.Speaker.tone(800, 60);
    }
    delay(600);

    // Принудительное стирание сообщения с экрана
    internalState.requiresRedraw = true;
}

void setup() {
    M5Cardputer.begin(M5.config(), true);
    M5.Lcd.setRotation(1);
    displaySprite.createSprite(SCREEN_WIDTH, SCREEN_HEIGHT);

    systemPreferences.begin("by_chillyc0de");
    internalState.timeSetupTimeInput = systemPreferences.getString("TA/time", MINIMUM_DATE);
    internalState.timeSetupUTCOffsetInput = systemPreferences.getInt("TA/utc", DEFAULT_UTC);
    internalState.brightnessSetupBrightnessCounter = systemPreferences.getInt("TA/brght", DEFAULT_BRIGHTNESS);
    internalState.volumeSetupVolumeCounter = systemPreferences.getInt("TA/vol", DEFAULT_VOLUME);
    M5.Display.setBrightness(internalState.brightnessSetupBrightnessCounter);
    M5.Speaker.setVolume(internalState.volumeSetupVolumeCounter);
    internalState.soundSetupExternalState = systemPreferences.getBool("TA/snd_es", DEFAULT_SOUND_ES);
    internalState.soundSetupKeyboard = systemPreferences.getInt("TA/snd_kbd", DEFAULT_SOUND_KBD);
    internalState.soundSetupTOTP = systemPreferences.getInt("TA/snd_totp", DEFAULT_SOUND_TOTP);
    internalState.soundSetupScreenshot = systemPreferences.getBool("TA/snd_scr", DEFAULT_SOUND_SCR);

    SPI.begin(40, 39, 14, 12);
    // Проверка наличия SD
    if (!SD.begin(12, SPI, 15000000)) { // 25000000
        drawMessage({"SD NOT FOUND", {"Insert SD and reboot", &fonts::Font2}});
        while (true) delay(10000);
    }

    USB.begin();
    usbKeyboard.begin();

    switchExternalState(STATE_SPLASH_SCREEN);
}

void loop() {
    switch (internalState.currentExternalState) {
    case STATE_SPLASH_SCREEN:
        // Анимация на экране загрузки
        static ulong lastSplashAnimationTime = 0;
        // Частота кадров 1к/33мс = 30к/с
        if (millis() - lastSplashAnimationTime > 33) {
            lastSplashAnimationTime = millis();
            internalState.requiresRedraw = true;
        }
        break;
    case STATE_LOGIN:
        // Особое сообщение о неправильном пароле
        if (internalState.loginErrorClearTime > 0 && (millis() - internalState.loginErrorClearTime) > 1500) {
            internalState.loginErrorClearTime = 0;
            internalState.requiresRedraw = true;
        }
    case STATE_CHANGE_PASSWORD:
        // Мигание курсора на экране
        static ulong lastCursorBlinkTime = 0;
        // Частота мигания 1к/100 мс = 10к/с
        if (millis() - lastCursorBlinkTime > 100) {
            lastCursorBlinkTime = millis();
            internalState.requiresRedraw = true;
        }
        break; // Общий для двух
    case STATE_VOLUME_SETUP:
        // Анимация спектра на экране настройки звука
        static ulong lastSpectrumAnimationTime = 0;
        // Частота кадров 1к/16мс = 62.5к/с
        if (millis() - lastSpectrumAnimationTime > 16) {
            lastSpectrumAnimationTime = millis();
            internalState.requiresRedraw = true;
        }
        break;
    case STATE_ACCOUNT_LIST:
    case STATE_VIEW_TOTP:
        // Обновление данных в реальном времени
        static time_t lastRedrawTime = 0;
        time_t currentEpochTime = time(NULL);
        if (currentEpochTime != lastRedrawTime) {
            lastRedrawTime = currentEpochTime;
            internalState.requiresRedraw = true;
        }
        break;
    }

    M5Cardputer.update();

    // Захват экрана перед главным обработчиком клавиатуры
    processScreenshotEvent();

    processKeyboardEvents();
    renderUserInterface();
}