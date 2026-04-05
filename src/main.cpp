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

#include <HTTPClient.h>
#include <WiFi.h>

#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"

#define MINIMUM_UNIX_TS 1775347200
#define MINIMUM_DATE "20260405000000"
#define DEFAULT_UTC 3
#define DEFAULT_BRIGHTNESS 80
#define DEFAULT_SCREEN_SAVER 30000
#define DEFAULT_VAULT_DEAUTH 120000
#define DEFAULT_VOLUME 50
#define DEFAULT_SOUND_ES false
#define DEFAULT_SOUND_KBD 1
#define DEFAULT_SOUND_SCR true
#define DEFAULT_SOUND_TOTP 1

const char *DATA_FILE_PATH = "/by_chillyc0de/TOTP_Auth/data";              // Без "/" в конце
const char *SCREEN_CAPTURE_DIR_PATH = "/by_chillyc0de/TOTP_Auth/captures"; // Без "/" в конце
const char *FIRMWARE_VERSION = "v1.6.1";

const int SCREEN_WIDTH = 240;
const int SCREEN_HEIGHT = 135;

const uint16_t UI_BG = 0x0000;
const uint16_t UI_FG = 0xFFFF;
const uint16_t UI_ACCENT = 0xE204;
const uint16_t UI_MUTED = 0x39E7;
const uint16_t UI_DANGER = 0xF800;
const uint16_t UI_VALID = 0x07E0;
const uint16_t UI_WARNING = 0xF3C6;

const int MAX_BASE32_DECODE_LENGTH = 128;
const int MAX_ACCOUNT_NAME_LENGTH = 32;

const String userGuideLines[] = {
    "============ TOTP AUTH ============",
    " Created by chillyc0de.",
    " Assisted by Google Gemini (LLM).",
    " Offline hardware authenticator",
    " for M5Stack Cardputer ADV.",
    "",
    "------- 1. GETTING STARTED --------",
    " 1) Set a Master Password for the vault.",
    " 2) Manually set the correct Date, Time",
    "    and UTC offset for synchronization.",
    " 3) Optionally, configure Wi-Fi in Settings",
    "    to automatically sync time over the network.",
    "",
    "----------- 2. ACCOUNTS -----------",
    " Secret keys must be Base32 (A-Z, 2-7 only).",
    " * View TOTP: Generate the current code.",
    " * View QR: Display QR code for migration.",
    " * Edit/Remove: Manage your accounts.",
    "",
    "-------- 3. USB AUTO-TYPE ---------",
    " Connect the device to a PC via USB.",
    " While viewing a TOTP code,",
    " press [Enter] to auto-type the code",
    " using USB HID keyboard emulation.",
    "",
    "-------- 4. AUDIO FEEDBACK --------",
    " * X-State: Off or Tone.",
    " * Keyboard: Off, Tone, or Morse.",
    " * TOTP: Off, Tone, or Morse.",
    " * Screen capture: Off or Tone.",
    "",
    "-------- 5. SCREEN CAPTURE --------",
    " Press [BtnGO+Ctrl] to take a screenshot.",
    " Press [BtnGO+Opt] to toggle recording.",
    " Saved as .bmp to SD card.",
    " Useful for debugging, README, etc.",
    "",
    "----------- 6. SECURITY -----------",
    " Vault: Encrypted data file.",
    " File path: /by_chillyc0de/TOTP_Auth/data",
    " If lost, data cannot be recovered.",
    " NO PASSWORD RECOVERY!",
    "",
    "----------- 7. SETTINGS -----------",
    " Press [Esc] in the Account list:",
    " * Wi-Fi: Connect to a network",
    "   (for automatic time sync).",
    " * Time: Re-sync the clock.",
    " * Brightness: Adjust brightness.",
    " * Volume: Adjust volume.",
    " * Sound: Off, Tones, or Morse.",
    " * Password: Change your Master Password.",
    "",
    "------- 8. LICENSE & RIGHTS -------",
    " Provided 'AS IS' under the MIT License.",
    " Use at your own risk. The author",
    " is not responsible for lost data",
    " or locked accounts.",
};
const int userGuideLinesSize = sizeof(userGuideLines) / sizeof(userGuideLines[0]);

// Перечисление типов внешних состояний
enum ExternalState : uint8_t {
    // Общие
    STATE_SPLASH,        // Заставка
    STATE_GUIDE,         // Руководство
    STATE_VAULT_AUTH,    // Аутентификация в хранилище
    STATE_TIME_CONFIG,   // Настройка времени
    STATE_SETTINGS_MENU, // Параметры

    // WiFi
    STATE_WIFI_CONFIG,  // Список доступных сетей
    STATE_WIFI_CONNECT, // Подключение к сети
    STATE_WIFI_REMOVAL, // Подтверждение удаления сети

    // Системные параметры
    STATE_BRIGHTNESS_ADJUST,     // Регулировка яркости
    STATE_VOLUME_ADJUST,         // Регулировка громкости
    STATE_SOUND_CONFIG,          // Настройки звука
    STATE_TIMEOUT_CONFIG,        // Настройки таймаутов для дисплея и деаутентификации
    STATE_VAULT_PASSWORD_CHANGE, // Смена пароля хранилища

    // Работа с данными
    STATE_ACCOUNT_LIST,      // Список аккаунтов
    STATE_ACCOUNT_EDITOR,    // Редактор аккаунта
    STATE_ACCOUNT_OPTIONS,   // Меню действий аккаунта
    STATE_ACCOUNT_TOTP_VIEW, // TOTP-код аккаунта
    STATE_ACCOUNT_QR_VIEW,   // QR-код аккаунта
    STATE_ACCOUNT_REMOVAL,   // Подтверждение удаления аккаунта
};

// Структура для внутренних состояний системы
struct InternalState {
    // ExternalState
    ExternalState currentExternalState = STATE_SPLASH;
    bool requiresRedraw = true;

    // Vault
    uint8_t salt[16];
    bool isSaltInitialized = false;
    bool isVaultAuthorized = false;

    // Time
    bool isTimeConfigured = false;

    // Battery
    int batteryLevel = 100;

    // Screen saver
    ulong lastKeyPressTime = 0;

    // Screen recording
    bool isScreenRecording = false;
    int screenRecordDirIndex = 0;
    int screenRecordFileIndex = 0;

    // STATE_GUIDE
    int Guide_ScrollY = 0;
    int Guide_ScrollX = 0;

    // STATE_VAULT_AUTH
    String VaultAuth_PasswordInput = "";
    bool VaultAuth_IsPasswordVisible = false;
    int VaultAuth_CursorPosition = 0;
    int VaultAuth_ScrollOffset = 0;

    // STATE_TIME_CONFIG
    String TimeConfig_TimeInput = MINIMUM_DATE;
    int TimeConfig_UTCOffsetInput = DEFAULT_UTC;

    // STATE_SETTINGS_MENU
    int SettingsMenu_SelectedIndex = 0;
    int SettingsMenu_ScrollOffset = 0;

    // STATE_WIFI_CONFIG
    int WiFiConfig_SelectedIndex = 0;
    int WiFiConfig_ScrollOffset = 0;

    // STATE_WIFI_CONNECT
    String WiFiConnect_PasswordInput = "";
    bool WiFiConnect_IsPasswordVisible = false;
    int WiFiConnect_CursorPosition = 0;
    int WiFiConnect_ScrollOffset = 0;

    // STATE_WIFI_REMOVAL
    bool WiFiRemoval_isPendingConfirmation = false;

    // STATE_BRIGHTNESS_ADJUST
    int BrightnessAdjust_BrightnessCounter = DEFAULT_BRIGHTNESS;

    // STATE_VOLUME_ADJUST
    int VolumeAdjust_VolumeCounter = DEFAULT_VOLUME;

    // STATE_SOUND_CONFIG
    int SoundConfig_FieldIndex = 0;
    bool SoundConfig_ExternalStateSound = DEFAULT_SOUND_ES;
    int SoundConfig_KeyboardSound = DEFAULT_SOUND_KBD;
    int SoundConfig_TOTPSound = DEFAULT_SOUND_TOTP;
    bool SoundConfig_ScreenCaptureSound = DEFAULT_SOUND_SCR;

    // STATE_TIMEOUT_CONFIG
    int TimeoutConfig_FieldIndex = 0;
    int TimeoutConfig_ScreenSaver = DEFAULT_SCREEN_SAVER;
    String TimeoutConfig_ScreenSaverInput = "";
    int TimeoutConfig_VaultDeauth = DEFAULT_VAULT_DEAUTH;
    String TimeoutConfig_VaultDeauthInput = "";

    // STATE_VAULT_PASSWORD_CHANGE
    String VaultPasswordChange_PasswordInput = "";
    bool VaultPasswordChange_IsPasswordVisible = false;
    int VaultPasswordChange_CursorPosition = 0;
    int VaultPasswordChange_ScrollOffset = 0;
    bool VaultPasswordChange_isPendingConfirmation = false;

    // STATE_ACCOUNT_LIST
    int AccountList_SelectedIndex = 0;
    int AccountList_ScrollOffset = 0;

    // STATE_ACCOUNT_EDITOR
    bool AccountEditor_IsEditMode = false;
    int AccountEditor_FieldIndex = 0;
    String AccountEditor_NameInput = "";
    String AccountEditor_KeyInput = "";
    int AccountEditor_AlgoInput = 0;
    int AccountEditor_DigitsInput = 6;
    int AccountEditor_PeriodInput = 30;

    // STATE_ACCOUNT_OPTIONS
    int AccountOptions_SelectedIndex = 0;
    int AccountOptions_ScrollOffset = 0;

    // STATE_ACCOUNT_REMOVAL
    bool AccountRemoval_isPendingConfirmation = false;
};
InternalState internalState;

// Структура для хранения аккаунтов, сохраняемых в хранилище
struct Account {
    String name;
    String key;
    int algo;
    int digits;
    int period;
};
std::vector<Account> savedAccounts;

// Структура для хранения Wi-Fi сетей, сохраняемых в хранилище
struct WiFiNetwork {
    String ssid;
    String password;
};
std::vector<WiFiNetwork> savedWiFiNetworks;

LGFX_Sprite displaySprite(&M5.Lcd);
Preferences systemPreferences;
USBHIDKeyboard usbKeyboard;

// --- ХЕЛПЕРЫ ДЛЯ WI-FI ---
bool isSavedSSID(const String &ssid) {
    for (const WiFiNetwork &w : savedWiFiNetworks) {
        if (w.ssid == ssid) return true;
    }
    return false;
}

bool isDiscoveredSSID(const String &ssid) {
    for (int i = 0; i < WiFi.scanComplete(); i++) {
        if (WiFi.SSID(i) == ssid) return true;
    }
    return false;
}

int getTotalWiFiNetworksCount() {
    // Сохранённые
    int totalCount = savedWiFiNetworks.size();

    // Обнаруженные, но не сохранённые
    for (int i = 0; i < WiFi.scanComplete(); i++) {
        if (!isSavedSSID(WiFi.SSID(i))) totalCount++;
    }
    return totalCount;
}

WiFiNetwork *getWiFiNetworkByIndex(int index, bool &isSaved, bool &isScanned) {
    static WiFiNetwork tempWn;
    tempWn.ssid = "";
    tempWn.password = "";
    int currentIndex = 0;

    // Обнаруженные и сохранённые
    for (WiFiNetwork &wn : savedWiFiNetworks) {
        if (isDiscoveredSSID(wn.ssid)) {
            if (index == currentIndex) {
                isSaved = true;
                isScanned = true;
                return &wn;
            }
            currentIndex++;
        }
    }
    // Только обнаруженные
    for (int i = 0; i < WiFi.scanComplete(); i++) {
        if (!isSavedSSID(WiFi.SSID(i))) {
            if (index == currentIndex) {
                isSaved = false;
                isScanned = true;

                tempWn.ssid = WiFi.SSID(i);
                tempWn.password = "";
                return &tempWn;
            }
            currentIndex++;
        }
    }
    // Только сохранённые
    for (WiFiNetwork &wn : savedWiFiNetworks) {
        if (!isDiscoveredSSID(wn.ssid)) {
            if (index == currentIndex) {
                isSaved = true;
                isScanned = false;
                return &wn;
            }
            currentIndex++;
        }
    }
    isSaved = false;
    isScanned = false;
    return &tempWn;
}
WiFiNetwork *getWiFiNetworkByIndex(int index) {
    bool isSaved, isScanned;
    return getWiFiNetworkByIndex(index, isSaved, isScanned);
}

// --- ЗВУКОВАЯ ИНДИКАЦИЯ ---
void playMorseCode(const char *code, float freq, uint32_t dot, uint32_t dash, uint32_t pause) {
    while (*code) {
        if (*code == '.') M5.Speaker.tone(freq, dot);
        else if (*code == '-') M5.Speaker.tone(freq, dash);
        delay(pause);
        code++;
    }
}

void playToneExternalState(ExternalState externalState) {
    if (internalState.VolumeAdjust_VolumeCounter == 0 || internalState.isScreenRecording) return;

    switch (externalState) {
    case STATE_SPLASH:
        M5.Speaker.tone(700, 80);
        delay(80);
        M5.Speaker.tone(900, 80);
        break;
    case STATE_GUIDE:
        M5.Speaker.tone(600, 100);
        delay(100);
        M5.Speaker.tone(800, 100);
        break;
    case STATE_VAULT_AUTH:
        M5.Speaker.tone(800, 60);
        delay(60);
        M5.Speaker.tone(1000, 60);
        break;
    case STATE_TIME_CONFIG:
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
    case STATE_WIFI_CONFIG:
        M5.Speaker.tone(900, 50);
        delay(50);
        M5.Speaker.tone(900, 50);
        break;
    case STATE_WIFI_CONNECT:
        M5.Speaker.tone(800, 100);
        delay(100);
        M5.Speaker.tone(1200, 100);
        break;
    case STATE_WIFI_REMOVAL:
        M5.Speaker.tone(1000, 80);
        delay(80);
        M5.Speaker.tone(800, 150);
        break;
    case STATE_BRIGHTNESS_ADJUST:
        M5.Speaker.tone(750, 60);
        delay(60);
        M5.Speaker.tone(1300, 60);
        break;
    case STATE_VOLUME_ADJUST:
        M5.Speaker.tone(750, 60);
        delay(60);
        M5.Speaker.tone(550, 60);
        break;
    case STATE_SOUND_CONFIG:
        M5.Speaker.tone(750, 60);
        delay(60);
        M5.Speaker.tone(850, 40);
        delay(40);
        M5.Speaker.tone(750, 60);
        break;
    case STATE_TIMEOUT_CONFIG:
        M5.Speaker.tone(1000, 20);
        delay(100);
        M5.Speaker.tone(800, 20);
        break;
    case STATE_VAULT_PASSWORD_CHANGE:
        M5.Speaker.tone(750, 60);
        delay(60);
        M5.Speaker.tone(500, 100);
        break;
    case STATE_ACCOUNT_LIST:
        M5.Speaker.tone(850, 60);
        delay(60);
        M5.Speaker.tone(1050, 80);
        break;
    case STATE_ACCOUNT_EDITOR:
        M5.Speaker.tone(1050, 60);
        delay(60);
        M5.Speaker.tone(1500, 80);
        break;
    case STATE_ACCOUNT_OPTIONS:
        M5.Speaker.tone(1050, 60);
        delay(60);
        M5.Speaker.tone(1200, 60);
        break;
    case STATE_ACCOUNT_TOTP_VIEW:
        M5.Speaker.tone(1050, 60);
        delay(60);
        M5.Speaker.tone(1350, 120);
        break;
    case STATE_ACCOUNT_QR_VIEW:
        M5.Speaker.tone(1050, 50);
        delay(50);
        M5.Speaker.tone(1150, 50);
        delay(50);
        M5.Speaker.tone(1250, 50);
        break;
    case STATE_ACCOUNT_REMOVAL:
        M5.Speaker.tone(1050, 80);
        delay(80);
        M5.Speaker.tone(500, 150);
        break;
    }
}

void playToneKeyboard(char kChar, Keyboard_Class::KeysState kState = {}) {
    if (internalState.VolumeAdjust_VolumeCounter == 0 || internalState.isScreenRecording) return;

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

void playMorseKeyboard(char kChar, Keyboard_Class::KeysState kState = {}) {
    if (internalState.VolumeAdjust_VolumeCounter == 0 || internalState.isScreenRecording) return;

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
            playMorseCode(morse, frequency, dot_duration, dash_duration, pause_duration);
            return;
        }
    }

    // Клавиши состояния
    if (kState.enter) {
        frequency = 1200;
        playMorseCode(".", frequency, dot_duration, dash_duration, pause_duration);  // E
        playMorseCode("-.", frequency, dot_duration, dash_duration, pause_duration); // N
        return;
    }
    if (kState.tab) {
        frequency = 1200;
        playMorseCode("-", frequency, dot_duration, dash_duration, pause_duration);    // T
        playMorseCode(".-", frequency, dot_duration, dash_duration, pause_duration);   // A
        playMorseCode("-...", frequency, dot_duration, dash_duration, pause_duration); // B
        return;
    }
    if (kState.del && !kState.fn) {
        frequency = 1200;
        playMorseCode("-...", frequency, dot_duration, dash_duration, pause_duration); // B
        return;
    }
    // Пробел
    if (kChar == ' ') {
        frequency = 900;
        playMorseCode("...", frequency, dot_duration, dash_duration, pause_duration);  // S
        playMorseCode(".--.", frequency, dot_duration, dash_duration, pause_duration); // P
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

    if (morse) playMorseCode(morse, frequency, dot_duration, dash_duration, pause_duration);
    else M5.Speaker.tone(frequency, 25);
}

void playKeyboardSound(char kChar, Keyboard_Class::KeysState kState = {}) {
    // Звуковая индикация
    switch (internalState.SoundConfig_KeyboardSound) {
    case 0:
        // Off
        break;
    case 1:
        // Simple
        playToneKeyboard(kChar, kState);
        break;
    case 2:
        // Morse
        playMorseKeyboard(kChar, kState);
        break;
    }
}

void playToneTOTP() {
    if (internalState.VolumeAdjust_VolumeCounter == 0 || internalState.isScreenRecording) return;

    M5.Speaker.tone(1500, 40);
    delay(50);
    M5.Speaker.tone(1800, 40);
    delay(50);
    M5.Speaker.tone(2000, 100);
    delay(200);
}

void playMorseTOTP(const String &totp) {
    if (internalState.VolumeAdjust_VolumeCounter == 0 || internalState.isScreenRecording) return;
    for (int i = 0; i < totp.length(); i++) {
        playMorseKeyboard(totp[i]);
        delay(100);
    }
}

void playToneScreenshot() {
    if (internalState.VolumeAdjust_VolumeCounter == 0 || internalState.isScreenRecording) return;
    M5.Speaker.tone(1000, 60);
    delay(40);
    M5.Speaker.tone(900, 60);
    delay(40);
    M5.Speaker.tone(800, 60);
}

void playToneScreenRecordingStart() {
    if (internalState.VolumeAdjust_VolumeCounter == 0) return;
    // Быстрое скольжение вверх
    for (int f = 800; f <= 1200; f += 200) {
        M5.Speaker.tone(f, 30);
        delay(30);
    }
}

void playToneScreenRecordingStop() {
    if (internalState.VolumeAdjust_VolumeCounter == 0) return;
    // Быстрое скольжение вниз
    for (int f = 1200; f >= 800; f -= 200) {
        M5.Speaker.tone(f, 30);
        delay(30);
    }
}

void playToneVaultDeauth() {
    if (internalState.VolumeAdjust_VolumeCounter == 0) return;

    // Первый тон: короткий клик
    M5.Speaker.tone(1200, 40);
    delay(50);

    // Второй тон: мягкое затухание
    for (int f = 1000; f >= 600; f -= 100) {
        M5.Speaker.tone(f, 40);
        delay(40);
    }
}

// --- ПЕРЕКЛЮЧЕНИЕ СОСТОЯНИЙ ---
void switchExternalState(ExternalState externalState) {
    internalState.currentExternalState = externalState;
    internalState.requiresRedraw = true;

    switch (externalState) {
    case STATE_VAULT_AUTH: {
        if (!internalState.isVaultAuthorized) break;
        else playToneVaultDeauth(); // Звуковая индикация

        // Затираем содержимое аккаунтов
        for (Account &acc : savedAccounts) {
            for (int i = 0; i < acc.name.length(); i++) acc.name[i] = '\0';
            acc.name = "";
            for (int i = 0; i < acc.key.length(); i++) acc.key[i] = '\0';
            acc.key = "";
        }
        savedAccounts.clear();
        savedAccounts.shrink_to_fit();

        // Затираем содержимое сетей
        for (WiFiNetwork &wn : savedWiFiNetworks) {
            for (int i = 0; i < wn.ssid.length(); i++) wn.ssid[i] = '\0';
            wn.ssid = "";
            for (int i = 0; i < wn.password.length(); i++) wn.password[i] = '\0';
            wn.password = "";
        }
        savedWiFiNetworks.clear();
        savedWiFiNetworks.shrink_to_fit();

        // Затираем соль
        esp_fill_random(internalState.salt, 16);
        internalState.isSaltInitialized = false;

        // Затираем пароль хранилища
        for (unsigned int i = 0; i < internalState.VaultAuth_PasswordInput.length(); i++) {
            internalState.VaultAuth_PasswordInput[i] = '\0';
        }
        internalState.VaultAuth_PasswordInput = "";
        internalState.VaultAuth_IsPasswordVisible = false;
        internalState.VaultAuth_CursorPosition = 0;
        internalState.VaultAuth_ScrollOffset = 0;

        // Затираем пароль сети
        for (unsigned int i = 0; i < internalState.WiFiConnect_PasswordInput.length(); i++) {
            internalState.WiFiConnect_PasswordInput[i] = '\0';
        }
        internalState.WiFiConnect_PasswordInput = "";
        internalState.WiFiConnect_IsPasswordVisible = false;
        internalState.WiFiConnect_CursorPosition = 0;
        internalState.WiFiConnect_ScrollOffset = 0;

        // Затираем пароль изменения
        for (unsigned int i = 0; i < internalState.VaultPasswordChange_PasswordInput.length(); i++) {
            internalState.VaultPasswordChange_PasswordInput[i] = '\0';
        }
        internalState.VaultPasswordChange_PasswordInput = "";
        internalState.VaultPasswordChange_IsPasswordVisible = false;
        internalState.VaultPasswordChange_CursorPosition = 0;
        internalState.VaultPasswordChange_ScrollOffset = 0;

        // Затираем измененные данные аккаунта
        for (unsigned int i = 0; i < internalState.AccountEditor_NameInput.length(); i++) {
            internalState.AccountEditor_NameInput[i] = '\0';
        }
        internalState.AccountEditor_NameInput = "";
        for (unsigned int i = 0; i < internalState.AccountEditor_KeyInput.length(); i++) {
            internalState.AccountEditor_KeyInput[i] = '\0';
        }
        internalState.AccountEditor_KeyInput = "";

        // Отмена аутентификации
        internalState.isVaultAuthorized = false;
        break;
    }
    case STATE_TIME_CONFIG: {
        // Подстановка текущего времени
        time_t nowTime = time(NULL);
        if (nowTime < MINIMUM_UNIX_TS) {
            internalState.TimeConfig_TimeInput = systemPreferences.getString("TA/time", MINIMUM_DATE);
            internalState.TimeConfig_UTCOffsetInput = systemPreferences.getInt("TA/utc", DEFAULT_UTC);
        } else {
            time_t localTime = nowTime + (internalState.TimeConfig_UTCOffsetInput * 3600);
            struct tm *t = gmtime(&localTime);
            char buf[16];
            strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", t);
            internalState.TimeConfig_TimeInput = String(buf);
        }
        break;
    }
    case STATE_WIFI_CONFIG:
        // Запуск асинхронного сканирования
        WiFi.mode(WIFI_STA);
        WiFi.scanNetworks(true);
        // Всегда переключаемся на первую строку
        internalState.WiFiConfig_SelectedIndex = 0;
        internalState.WiFiConfig_ScrollOffset = 0;
        break;
    case STATE_WIFI_CONNECT:
        // Подстановка пароля сети
        internalState.WiFiConnect_PasswordInput = getWiFiNetworkByIndex(internalState.WiFiConfig_SelectedIndex)->password;
        internalState.WiFiConnect_IsPasswordVisible = false;
        internalState.WiFiConnect_CursorPosition = 0;
        internalState.WiFiConnect_ScrollOffset = 0;
        break;
    case STATE_TIMEOUT_CONFIG:
        // Подстановка значений таймаутов
        internalState.TimeoutConfig_ScreenSaverInput = String(internalState.TimeoutConfig_ScreenSaver / 1000);
        internalState.TimeoutConfig_VaultDeauthInput = String(internalState.TimeoutConfig_VaultDeauth / 1000);
        break;
    case STATE_ACCOUNT_EDITOR:
        // Подстановка данных аккаунта в режиме редактирования
        if (internalState.AccountEditor_IsEditMode) {
            Account acc = savedAccounts[internalState.AccountList_SelectedIndex - 1];
            internalState.AccountEditor_FieldIndex = 0;
            internalState.AccountEditor_NameInput = acc.name;
            internalState.AccountEditor_KeyInput = acc.key;
            internalState.AccountEditor_AlgoInput = acc.algo;
            internalState.AccountEditor_DigitsInput = acc.digits;
            internalState.AccountEditor_PeriodInput = acc.period;
        }
        break;
    }

    // Звуковая индикация
    if (internalState.SoundConfig_ExternalStateSound) playToneExternalState(externalState);
}

// --- СТАТИЧНЫЕ МЕНЮ ---
struct MenuOption {
    String label;
    std::function<void()> action;
};

const MenuOption settingsMenuOptions[] = {
    {
        "Return to accounts",
        []() {
            switchExternalState(STATE_ACCOUNT_LIST);
        },
    },
    {
        "Deauthorize vault",
        []() {
            switchExternalState(STATE_VAULT_AUTH);
        },
    },
    {
        "Configure Wi-Fi",
        []() {
            switchExternalState(STATE_WIFI_CONFIG);
        },
    },
    {
        "Configure time",
        []() {
            switchExternalState(STATE_TIME_CONFIG);
        },
    },
    {
        "Adjust brightness",
        []() {
            switchExternalState(STATE_BRIGHTNESS_ADJUST);
        },
    },
    {
        "Adjust volume",
        []() {
            switchExternalState(STATE_VOLUME_ADJUST);
        },
    },
    {
        "Configure sound",
        []() {
            switchExternalState(STATE_SOUND_CONFIG);
        },
    },
    {
        "Configure timeout",
        []() {
            switchExternalState(STATE_TIMEOUT_CONFIG);
        },
    },
    {
        "Change vault password",
        []() {
            switchExternalState(STATE_VAULT_PASSWORD_CHANGE);
        },
    },
};
const int settingsMenuOptionsSize = sizeof(settingsMenuOptions) / sizeof(settingsMenuOptions[0]);

const MenuOption actionMenuOptions[] = {
    {
        "View TOTP",
        []() {
            switchExternalState(STATE_ACCOUNT_TOTP_VIEW);
        },
    },
    {
        "View QR",
        []() {
            switchExternalState(STATE_ACCOUNT_QR_VIEW);
        },
    },
    {
        "Edit",
        []() {
            // Переход в состояние с режимом редактирования
            internalState.AccountEditor_IsEditMode = true;
            switchExternalState(STATE_ACCOUNT_EDITOR);
        },
    },
    {
        "Remove",
        []() {
            switchExternalState(STATE_ACCOUNT_REMOVAL);
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
    mbedtls_platform_zeroize(key, sizeof(key));
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
void ensureDirectoryExists(const String &dirPath, bool isFilePath = false) {
    String fullPath = dirPath;

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
void ensureDirectoryExists(const char *dirPath, bool isFilePath = false) {
    ensureDirectoryExists(String(dirPath), isFilePath);
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
    savedWiFiNetworks.clear();

    // Совместимость версий прошивки
    if (doc.is<JsonArray>()) {
        // Старый формат (только аккаунты)
        for (JsonObject obj : doc.as<JsonArray>()) {
            Account acc;
            acc.name = obj["n"].as<String>();
            acc.key = obj["s"].as<String>();
            acc.algo = obj["a"].is<int>() ? obj["a"].as<int>() : 0;
            acc.digits = obj["d"].is<int>() ? obj["d"].as<int>() : 6;
            acc.period = obj["p"].is<int>() ? obj["p"].as<int>() : 30;
            savedAccounts.push_back(acc);
        }
    } else if (doc.is<JsonObject>()) {
        // Новый формат (аккаунты + сети)
        JsonArray accArr = doc["accounts"].as<JsonArray>();
        for (JsonObject obj : accArr) {
            Account acc;
            acc.name = obj["n"].as<String>();
            acc.key = obj["s"].as<String>();
            acc.algo = obj["a"].is<int>() ? obj["a"].as<int>() : 0;
            acc.digits = obj["d"].is<int>() ? obj["d"].as<int>() : 6;
            acc.period = obj["p"].is<int>() ? obj["p"].as<int>() : 30;
            savedAccounts.push_back(acc);
        }

        JsonArray wifiArr = doc["wifi"].as<JsonArray>();
        for (JsonObject obj : wifiArr) {
            WiFiNetwork net;
            net.ssid = obj["s"].as<String>();
            net.password = obj["p"].as<String>();
            savedWiFiNetworks.push_back(net);
        }
    }
    return true;
}

String serializeVaultJSON() {
    JsonDocument doc;
    JsonObject root = doc.to<JsonObject>();

    JsonArray accArr = root["accounts"].to<JsonArray>();
    for (const Account &acc : savedAccounts) {
        JsonObject obj = accArr.add<JsonObject>();
        obj["n"] = acc.name;
        obj["s"] = acc.key;
        obj["a"] = acc.algo;
        obj["d"] = acc.digits;
        obj["p"] = acc.period;
    }

    JsonArray wifiArr = root["wifi"].to<JsonArray>();
    for (const WiFiNetwork &net : savedWiFiNetworks) {
        JsonObject obj = wifiArr.add<JsonObject>();
        obj["s"] = net.ssid;
        obj["p"] = net.password;
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
    // Очищаем ключ в стеке перед выходом
    mbedtls_platform_zeroize(key, sizeof(key));

    decBuf.resize(encBuf.size());
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, encBuf.size(), iv_copy, encBuf.data(), decBuf.data());
    mbedtls_aes_free(&aes);

    uint8_t padLen = decBuf.back();
    if (padLen > 16 || padLen == 0 || padLen > encBuf.size()) {
        mbedtls_platform_zeroize(decBuf.data(), decBuf.size()); // ЗАТИРАЕМ
        return false;
    }
    for (size_t i = encBuf.size() - padLen; i < encBuf.size(); i++) {
        if (decBuf[i] != padLen) {
            mbedtls_platform_zeroize(decBuf.data(), decBuf.size()); // ЗАТИРАЕМ
            return false;
        }
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
    // Очищаем ключ в стеке перед выходом
    mbedtls_platform_zeroize(key, sizeof(key));

    encBuf.resize(paddedLen);
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedLen, iv_copy, plainBuf.data(), encBuf.data());
    mbedtls_aes_free(&aes);
    mbedtls_platform_zeroize(plainBuf.data(), plainBuf.size());
}

bool loadDataFromStorage() {
    if (!SD.exists(DATA_FILE_PATH)) return true;

    uint8_t salt[16], iv[16];
    std::vector<uint8_t> encBuf, decBuf;

    if (!readVaultFromSD(salt, iv, encBuf)) return false;

    // Если дешифровка не удалась
    if (!decryptVault(encBuf, salt, iv, internalState.VaultAuth_PasswordInput, decBuf)) {
        mbedtls_platform_zeroize(decBuf.data(), decBuf.size()); // Затираем
        return false;
    }

    // Если парсинг не удался
    if (!parseVaultJSON(decBuf)) {
        mbedtls_platform_zeroize(decBuf.data(), decBuf.size()); // Затираем
        return false;
    }

    // Если всё ок — данные уже в объектах, затираем временный буфер
    mbedtls_platform_zeroize(decBuf.data(), decBuf.size());

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

void saveDataToStorage() {
    if (!internalState.isSaltInitialized) {
        esp_fill_random(internalState.salt, 16);
        internalState.isSaltInitialized = true;
    }

    uint8_t iv[16];
    esp_fill_random(iv, 16); // Генерируем чистый IV

    String jsonStr = serializeVaultJSON();
    std::vector<uint8_t> encBuf;

    encryptVault(jsonStr, internalState.salt, iv, internalState.VaultAuth_PasswordInput, encBuf);
    writeVaultToSD(internalState.salt, iv, encBuf);

    // Затираем временную JSON строку
    for (unsigned int i = 0; i < jsonStr.length(); i++) {
        jsonStr[i] = '\0';
    }
    jsonStr = "";

    // encBuf можно просто очистить, там зашифрованные данные
    encBuf.clear();
    encBuf.shrink_to_fit();
}

void performVaultPasswordChange() {
    // Генерируем новую соль, чтобы старые хеши были бесполезны
    esp_fill_random(internalState.salt, 16);
    internalState.isSaltInitialized = true;

    // Обновляем основной пароль в памяти
    internalState.VaultAuth_PasswordInput = internalState.VaultPasswordChange_PasswordInput;

    // Перезаписываем файл с новым ключом и новой солью
    saveDataToStorage();
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
    int numLines = std::min((int)lines.size(), 2);

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
void drawDebug(const std::vector<MessageLine> &lines, int messageDelay = 1000) {
    drawMessage(lines, UI_WARNING, UI_MUTED);
    delay(messageDelay);
}

// --- ОТРИСОВКА ЭКРАНОВ ---
void renderSplash() {
    displaySprite.fillSprite(UI_BG);
    drawFooter({"   [Any]: Guide       [Enter]: Auth"});

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

void renderGuide() {
    displaySprite.fillSprite(UI_BG);
    drawHeader("GUIDE");
    drawScrollbar(internalState.Guide_ScrollY / 18, (SCREEN_HEIGHT - 44) / 18, userGuideLinesSize, 26, SCREEN_HEIGHT - 46);
    drawFooter({"   [Esc]: Back      [Arrows]: Scroll"});

    displaySprite.setClipRect(0, 26, SCREEN_WIDTH - 5, SCREEN_HEIGHT - 44);

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(top_left);
    displaySprite.setFont(&fonts::Font2);

    for (int i = 0; i < userGuideLinesSize; i++) {
        int yPos = 30 + (i * 18) - internalState.Guide_ScrollY;
        if (yPos > -18 && yPos < SCREEN_HEIGHT) displaySprite.drawString(userGuideLines[i], 5 - internalState.Guide_ScrollX, yPos);
    }
    displaySprite.clearClipRect();
}

void renderVaultAuth() {
    const int charWidth = 24;
    const int maxCharsPerLine = 10;
    const int linesPerPage = 2;

    // Подготовка отображаемого текста
    String rawPassword = internalState.VaultAuth_PasswordInput;
    if (!internalState.VaultAuth_IsPasswordVisible) {
        rawPassword = "";
        for (int i = 0; i < (int)internalState.VaultAuth_PasswordInput.length(); i++) rawPassword += "*";
    }

    // Нарезка на строки
    std::vector<String> lines;
    if (rawPassword.length() == 0) lines.push_back("");
    else {
        for (int i = 0; i < (int)rawPassword.length(); i += maxCharsPerLine) {
            lines.push_back(rawPassword.substring(i, min(i + maxCharsPerLine, (int)rawPassword.length())));
        }
        // Если курсор на новой строке
        if (internalState.VaultAuth_CursorPosition > 0 && internalState.VaultAuth_CursorPosition % maxCharsPerLine == 0 && internalState.VaultAuth_CursorPosition == (int)internalState.VaultAuth_PasswordInput.length()) {
            lines.push_back("");
        }
    }

    // Авто-скролл
    int cursorLineIdx = internalState.VaultAuth_CursorPosition / maxCharsPerLine;
    if (cursorLineIdx < internalState.VaultAuth_ScrollOffset) internalState.VaultAuth_ScrollOffset = cursorLineIdx;
    if (cursorLineIdx >= internalState.VaultAuth_ScrollOffset + linesPerPage) internalState.VaultAuth_ScrollOffset = cursorLineIdx - (linesPerPage - 1);

    displaySprite.fillSprite(UI_BG);
    drawHeader("VAULT AUTH");
    drawFooter({" [Tab]: Show/Hide  [FN+Arrows]: Cursor", " [FN+Esc]:  Guide  [Enter]:    Confirm"});

    displaySprite.setTextColor(UI_VALID);
    displaySprite.setTextDatum(middle_center);

    // Вычисляем стартовую X-координату для центрирования всего БЛОКА (10 символов)
    int startX = (SCREEN_WIDTH - maxCharsPerLine * charWidth) / 2 + (charWidth / 2);
    for (int i = 0; i < linesPerPage; i++) {
        int lineIdx = internalState.VaultAuth_ScrollOffset + i;

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
            int cursorXInLine = internalState.VaultAuth_CursorPosition % maxCharsPerLine;

            // Сдвигаем курсор на левый край текущей ячейки символа
            int cursorX = startX + (cursorXInLine * charWidth) - (charWidth / 2);

            // Рисуем курсор
            displaySprite.fillRect(cursorX, yPos - 12, 2, 24, UI_ACCENT);
        }
    }
}

void renderTimeConfig() {
    String dateMask = "____ - __ - __";
    String timeMask = "__ : __ : __";
    for (int i = 0; i < (int)internalState.TimeConfig_TimeInput.length(); i++) {
        if (i < 8) {
            int pos = (i < 4) ? i : (i < 6) ? i + 3
                                            : i + 6;
            dateMask[pos] = internalState.TimeConfig_TimeInput[i];
        } else {
            int timeIdx = i - 8;
            int pos = (timeIdx < 2) ? timeIdx : (timeIdx < 4) ? timeIdx + 3
                                                              : timeIdx + 6;
            timeMask[pos] = internalState.TimeConfig_TimeInput[i];
        }
    }

    displaySprite.fillSprite(UI_BG);
    String utcString = "UTC" + String(internalState.TimeConfig_UTCOffsetInput >= 0 ? "+" : "") + String(internalState.TimeConfig_UTCOffsetInput);
    drawHeader("TIME CONFIG", utcString);
    drawFooter({"  [Esc]:   Back [Tab]: Sync via Wi-Fi", "  [Arrows]: UTC [Enter]:      Confirm"});

    displaySprite.setTextDatum(middle_center);
    displaySprite.setFont(&fonts::Font4);

    displaySprite.setTextColor(internalState.TimeConfig_TimeInput.length() >= 8 ? UI_VALID : UI_FG);
    displaySprite.drawString(dateMask, SCREEN_WIDTH / 2, 52); // 58

    displaySprite.setTextColor(internalState.TimeConfig_TimeInput.length() == 14 ? UI_VALID : UI_FG);
    displaySprite.drawString(timeMask, SCREEN_WIDTH / 2, 85); // 93
}

void renderSettingsMenu() {
    displaySprite.fillSprite(UI_BG);
    drawHeader("SETTINGS MENU");
    drawScrollbar(internalState.SettingsMenu_ScrollOffset, 4, settingsMenuOptionsSize, 32, 79);
    drawFooter({"   [Esc]: Guide      [Enter]: Select"});

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_center);

    for (int i = 0; i < 4; i++) {
        int itemIdx = internalState.SettingsMenu_ScrollOffset + i;
        if (itemIdx >= settingsMenuOptionsSize) break; // Если пунктов меньше 4, выходим раньше

        bool isSel = (itemIdx == internalState.SettingsMenu_SelectedIndex);
        int yPos = 32 + (i * 20); // i от 0 до 3 (позиция на экране)

        displaySprite.fillRect(20, yPos, 200, 18, isSel ? UI_ACCENT : UI_BG);
        displaySprite.drawString(settingsMenuOptions[itemIdx].label, SCREEN_WIDTH / 2, yPos + 9, &fonts::Font2);
    }
}

void renderWiFiConfig() {
    displaySprite.fillSprite(UI_BG);
    drawHeader("Wi-Fi CONFIG", "Net: " + (String)WiFi.scanComplete());
    drawFooter({" [Esc]: Bck [Del]: Rmv [Enter]: Select"});

    displaySprite.setTextDatum(middle_center);

    int scanResult = WiFi.scanComplete();
    if (scanResult == WIFI_SCAN_RUNNING) {
        displaySprite.drawString("Scan is   ", SCREEN_WIDTH / 2, SCREEN_HEIGHT / 2 - 10, &fonts::Font4);
        displaySprite.drawString("running...", SCREEN_WIDTH / 2, SCREEN_HEIGHT / 2 + 20, &fonts::Font4);
        return;
    }
    if (scanResult == WIFI_SCAN_FAILED) {
        displaySprite.drawString("Scan   ", SCREEN_WIDTH / 2, SCREEN_HEIGHT / 2 - 10, &fonts::Font4);
        displaySprite.drawString("failed!", SCREEN_WIDTH / 2, SCREEN_HEIGHT / 2 + 20, &fonts::Font4);
        return;
    }
    int totalCount = getTotalWiFiNetworksCount();
    if (totalCount == 0) {
        displaySprite.drawString("No Wi-Fi?", SCREEN_WIDTH / 2, SCREEN_HEIGHT / 2 - 10, &fonts::Font4);
        displaySprite.drawString("   O_O   ", SCREEN_WIDTH / 2, SCREEN_HEIGHT / 2 + 20, &fonts::Font4);
        return;
    }

    // Скроллбар на 5 строк
    drawScrollbar(internalState.WiFiConfig_ScrollOffset, 5, totalCount, 28, 87);

    displaySprite.setTextDatum(middle_left);
    for (int i = 0; i < 5; i++) {
        int idx = internalState.WiFiConfig_ScrollOffset + i;
        if (idx < totalCount) {
            bool isSaved, isScanned;
            WiFiNetwork *wn = getWiFiNetworkByIndex(idx, isSaved, isScanned);

            if (isSaved && isScanned) displaySprite.setTextColor(UI_VALID);
            else if (!isSaved && isScanned) displaySprite.setTextColor(UI_FG);
            else displaySprite.setTextColor(UI_MUTED);

            int yPos = 28 + (i * 18);

            // Отрисовка фона выделения
            displaySprite.fillRect(2, yPos, SCREEN_WIDTH - 12, 14, (idx == internalState.WiFiConfig_SelectedIndex) ? UI_ACCENT : UI_BG);

            // Отрисовка текста
            displaySprite.drawString(wn->ssid, 4, yPos + 8, &fonts::Font0);
        }
    }
}

void renderWiFiConnect() {
    const int charWidth = 24;
    const int maxCharsPerLine = 10;
    const int linesPerPage = 2;

    // Подготовка отображаемого текста
    String rawPassword = internalState.WiFiConnect_PasswordInput;
    if (!internalState.WiFiConnect_IsPasswordVisible) {
        rawPassword = "";
        for (int i = 0; i < (int)internalState.WiFiConnect_PasswordInput.length(); i++) rawPassword += "*";
    }

    // Нарезка на строки
    std::vector<String> lines;
    if (rawPassword.length() == 0) lines.push_back("");
    else {
        for (int i = 0; i < (int)rawPassword.length(); i += maxCharsPerLine) {
            lines.push_back(rawPassword.substring(i, min(i + maxCharsPerLine, (int)rawPassword.length())));
        }
        // Если курсор на новой строке
        if (internalState.WiFiConnect_CursorPosition > 0 && internalState.WiFiConnect_CursorPosition % maxCharsPerLine == 0 && internalState.WiFiConnect_CursorPosition == (int)internalState.WiFiConnect_PasswordInput.length()) {
            lines.push_back("");
        }
    }

    // Авто-скролл
    int cursorLineIdx = internalState.WiFiConnect_CursorPosition / maxCharsPerLine;
    if (cursorLineIdx < internalState.WiFiConnect_ScrollOffset) internalState.WiFiConnect_ScrollOffset = cursorLineIdx;
    if (cursorLineIdx >= internalState.WiFiConnect_ScrollOffset + linesPerPage) internalState.WiFiConnect_ScrollOffset = cursorLineIdx - (linesPerPage - 1);

    displaySprite.fillSprite(UI_BG);
    drawHeader(getWiFiNetworkByIndex(internalState.WiFiConfig_SelectedIndex)->ssid);
    drawFooter({" [Tab]: Show/Hide  [FN+Arrows]: Cursor", " [FN+Esc]:   Back  [Enter]:    Connect"});

    displaySprite.setTextColor(UI_VALID);
    displaySprite.setTextDatum(middle_center);

    // Вычисляем стартовую X-координату для центрирования всего БЛОКА (10 символов)
    int startX = (SCREEN_WIDTH - maxCharsPerLine * charWidth) / 2 + (charWidth / 2);
    for (int i = 0; i < linesPerPage; i++) {
        int lineIdx = internalState.WiFiConnect_ScrollOffset + i;

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
            int cursorXInLine = internalState.WiFiConnect_CursorPosition % maxCharsPerLine;

            // Сдвигаем курсор на левый край текущей ячейки символа
            int cursorX = startX + (cursorXInLine * charWidth) - (charWidth / 2);

            // Рисуем курсор
            displaySprite.fillRect(cursorX, yPos - 12, 2, 24, UI_ACCENT);
        }
    }
}

void renderWiFiRemoval() {
    displaySprite.fillSprite(UI_BG);
    drawHeader(getWiFiNetworkByIndex(internalState.WiFiConfig_SelectedIndex)->ssid);
    if (internalState.WiFiRemoval_isPendingConfirmation) {
        // Выводим подсказку вместо футера
        drawFooter({"      PRESS ENTER AGAIN TO CONFIRM"});
    } else {
        // Стандартный футер
        drawFooter({"   [Esc]: Cancel    [Enter]: Confirm"});
    }

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_center);
    displaySprite.drawString("Remove this?", SCREEN_WIDTH / 2, 60, &fonts::Font4);

    displaySprite.setTextColor(UI_DANGER);
    displaySprite.drawString("This action is permanent.", SCREEN_WIDTH / 2, 90, &fonts::Font2);
}

void renderBrightnessAdjust() {
    displaySprite.fillSprite(UI_BG);
    drawHeader("BRIGHTNESS ADJUST");
    drawProgressBar((float)internalState.BrightnessAdjust_BrightnessCounter / 255.0f, UI_VALID);
    drawFooter({"[Esc]: Back  [Arrows]: Led [Enter]: Adj"});

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

void renderVolumeAdjust() {
    displaySprite.fillSprite(UI_BG);
    drawHeader("VOLUME ADJUST");
    drawProgressBar((float)internalState.VolumeAdjust_VolumeCounter / 255.0f, UI_DANGER);
    drawFooter({"[Esc]: Back  [Arrows]: Vol [Enter]: Adj"});

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
    float volMultiplier = internalState.VolumeAdjust_VolumeCounter / 255.0f;
    for (int i = 0; i < numBars; i++) {
        float noise = (sin(millis() / 150.0f + i * 0.8f) + 1.0f) / 2.0f;
        int maxH = h - 6;
        int barH = (int)(maxH * volMultiplier * noise);

        if (internalState.VolumeAdjust_VolumeCounter > 0 && barH < 2) barH = 2;

        int bx = x + 2 + (int)(i * barStep);
        int by = y + h - barH - 2;

        // Столбик
        displaySprite.fillRect(bx, by, barW, barH, UI_DANGER);

        // Пик
        displaySprite.fillRect(bx, by - 2, barW, 1, UI_FG);
    }
}

void renderSoundConfig() {
    const char *kbdModes[] = {"OFF", "SIMPLE", "MORSE"};
    const char *totpModes[] = {"OFF", "SIMPLE", "MORSE"};
    String fields[4] = {
        "X-State: < " + String(internalState.SoundConfig_ExternalStateSound ? "ON" : "OFF") + " >",
        "Keyboard: < " + String(kbdModes[internalState.SoundConfig_KeyboardSound]) + " >",
        "TOTP: < " + String(totpModes[internalState.SoundConfig_TOTPSound]) + " >",
        "Screen capture: < " + String(internalState.SoundConfig_ScreenCaptureSound ? "ON" : "OFF") + " >",
    };

    displaySprite.fillSprite(UI_BG);
    drawHeader("SOUND CONFIG");
    drawFooter({"   [Tab]: Switch    [Arrows]: Change", "   [Esc]: Cancel    [Enter]: Confirm"});

    displaySprite.setTextDatum(top_left);
    displaySprite.setFont(&fonts::Font2);

    for (int i = 0; i < 4; i++) {
        displaySprite.setTextColor(internalState.SoundConfig_FieldIndex == i ? UI_VALID : UI_FG);
        displaySprite.drawString(fields[i], 10, 34 + (i * 15));
    }
}

void renderTimeoutConfig() {
    String fields[2] = {
        "Screen Saver: " + internalState.TimeoutConfig_ScreenSaverInput + " sec",
        "Vault Lock: " + internalState.TimeoutConfig_VaultDeauthInput + " sec",
    };

    displaySprite.fillSprite(UI_BG);
    drawHeader("TIMEOUT CONFIG");
    drawFooter({"   [Tab]: Switch    [0-9]:      Type", "   [Esc]: Cancel    [Enter]: Confirm"});

    displaySprite.setTextDatum(top_left);
    displaySprite.setFont(&fonts::Font2);

    for (int i = 0; i < 2; i++) {
        displaySprite.setTextColor(internalState.TimeoutConfig_FieldIndex == i ? UI_VALID : UI_FG);
        displaySprite.drawString(fields[i], 10, 38 + (i * 20));
    }

    // Сноска 0 = infinity
    displaySprite.setTextColor(UI_FG);
    displaySprite.drawString("* 0 sec = infinity (always ON)", 10, 80);
}

void renderVaultPasswordChange() {
    const int charWidth = 24;
    const int maxCharsPerLine = 10;
    const int linesPerPage = 2;

    // Подготовка отображаемого текста
    String rawPassword = internalState.VaultPasswordChange_PasswordInput;
    if (!internalState.VaultPasswordChange_IsPasswordVisible) {
        rawPassword = "";
        for (int i = 0; i < (int)internalState.VaultPasswordChange_PasswordInput.length(); i++) rawPassword += "*";
    }

    // Нарезка на строки
    std::vector<String> lines;
    if (rawPassword.length() == 0) lines.push_back("");
    else {
        for (int i = 0; i < (int)rawPassword.length(); i += maxCharsPerLine) {
            lines.push_back(rawPassword.substring(i, min(i + maxCharsPerLine, (int)rawPassword.length())));
        }
        // Если курсор на новой строке
        if (internalState.VaultPasswordChange_CursorPosition > 0 && internalState.VaultPasswordChange_CursorPosition % maxCharsPerLine == 0 && internalState.VaultPasswordChange_CursorPosition == (int)internalState.VaultPasswordChange_PasswordInput.length()) {
            lines.push_back("");
        }
    }

    // Авто-скролл
    int cursorLineIdx = internalState.VaultPasswordChange_CursorPosition / maxCharsPerLine;
    if (cursorLineIdx < internalState.VaultPasswordChange_ScrollOffset) internalState.VaultPasswordChange_ScrollOffset = cursorLineIdx;
    if (cursorLineIdx >= internalState.VaultPasswordChange_ScrollOffset + linesPerPage) internalState.VaultPasswordChange_ScrollOffset = cursorLineIdx - (linesPerPage - 1);

    displaySprite.fillSprite(UI_BG);
    drawHeader("VAULT PASSWORD CHANGE");
    if (internalState.VaultPasswordChange_isPendingConfirmation) {
        // Выводим подсказку вместо футера
        drawFooter({"      PRESS ENTER AGAIN TO CONFIRM"});
    } else {
        // Стандартный футер
        drawFooter({" [Tab]: Show/Hide  [FN+Arrows]: Cursor", " [FN+Esc]:   Back  [Enter]:    Confirm"});
    }

    displaySprite.setTextColor(UI_VALID);
    displaySprite.setTextDatum(middle_center);

    // Вычисляем стартовую X-координату для центрирования всего БЛОКА (10 символов)
    int startX = (SCREEN_WIDTH - maxCharsPerLine * charWidth) / 2 + (charWidth / 2);
    for (int i = 0; i < linesPerPage; i++) {
        int lineIdx = internalState.VaultPasswordChange_ScrollOffset + i;

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
            int cursorXInLine = internalState.VaultPasswordChange_CursorPosition % maxCharsPerLine;

            // Сдвигаем курсор на левый край текущей ячейки символа
            int cursorX = startX + (cursorXInLine * charWidth) - (charWidth / 2);

            // Рисуем курсор
            displaySprite.fillRect(cursorX, yPos - 12, 2, 24, UI_ACCENT);
        }
    }
}

void renderAccountList() {
    time_t localTime = time(NULL) + (internalState.TimeConfig_UTCOffsetInput * 3600);
    struct tm *t = gmtime(&localTime);
    char timeStr[24];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", t);

    displaySprite.fillSprite(UI_BG);
    drawHeader(timeStr, "Bat: " + String(internalState.batteryLevel) + "%");
    drawScrollbar(internalState.AccountList_ScrollOffset, 4, savedAccounts.size() + 1, 28, 86);
    drawFooter({"   [Esc]: Settings  [Enter]: Options"});

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_left);

    for (int i = 0; i < 4; i++) {
        int idx = internalState.AccountList_ScrollOffset + i;
        int yPos = 28 + (i * 22);
        if (idx <= (int)savedAccounts.size()) {
            bool isSel = (idx == internalState.AccountList_SelectedIndex);
            displaySprite.fillRect(4, yPos, SCREEN_WIDTH - 12, 20, isSel ? UI_ACCENT : UI_BG);

            String txt = (idx == 0) ? "      [ Create new account ]" : savedAccounts[idx - 1].name;
            displaySprite.drawString(txt, 12, yPos + 10, &fonts::Font2);
        }
    }
}

void renderAccountEditor() {
    const char *algos[] = {"SHA1", "SHA256", "SHA512"};
    String fields[5] = {
        "Name: " + internalState.AccountEditor_NameInput,
        "Key: " + internalState.AccountEditor_KeyInput,
        "Algo: < " + String(algos[internalState.AccountEditor_AlgoInput]) + " >",
        "Digits: < " + String(internalState.AccountEditor_DigitsInput) + " >",
        "Period: < " + String(internalState.AccountEditor_PeriodInput) + "s >",
    };

    displaySprite.fillSprite(UI_BG);
    drawHeader(internalState.AccountEditor_IsEditMode ? "ACCOUNT EDITOR" : "NEW ACCOUNT");
    drawFooter({"   [Tab]: Switch    [Arrows]: Change", "   [Esc]: Cancel    [Enter]: Confirm"});

    displaySprite.setTextDatum(top_left);
    displaySprite.setFont(&fonts::Font2);

    for (int i = 0; i < 5; i++) {
        displaySprite.setTextColor(internalState.AccountEditor_FieldIndex == i ? UI_VALID : UI_FG);
        displaySprite.drawString(fields[i], 10, 26 + (i * 15));
    }
}

void renderAccountOptions() {
    displaySprite.fillSprite(UI_BG);
    drawHeader(savedAccounts[internalState.AccountList_SelectedIndex - 1].name);
    drawScrollbar(internalState.AccountOptions_ScrollOffset, 4, actionMenuOptionsSize, 32, 4 * 20);
    drawFooter({"   [Esc]: Back       [Enter]: Select"});

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_center);

    for (int i = 0; i < 4; i++) {
        int itemIdx = internalState.AccountOptions_ScrollOffset + i;
        if (itemIdx >= actionMenuOptionsSize) break; // Если пунктов меньше 4, выходим раньше

        bool isSel = (itemIdx == internalState.AccountOptions_SelectedIndex);
        int yPos = 32 + (i * 20); // i от 0 до 3 (позиция на экране)

        displaySprite.fillRect(20, yPos, 200, 18, isSel ? UI_ACCENT : UI_BG);
        displaySprite.drawString(actionMenuOptions[itemIdx].label, SCREEN_WIDTH / 2, yPos + 9, &fonts::Font2);
    }
}

void renderAccountTOTP() {
    time_t now = time(NULL);
    Account acc = savedAccounts[internalState.AccountList_SelectedIndex - 1];
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

void renderAccountQR() {
    Account acc = savedAccounts[internalState.AccountList_SelectedIndex - 1];
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

void renderAccountRemoval() {
    displaySprite.fillSprite(UI_BG);
    drawHeader(savedAccounts[internalState.AccountList_SelectedIndex - 1].name);
    if (internalState.AccountRemoval_isPendingConfirmation) {
        // Выводим подсказку вместо футера
        drawFooter({"      PRESS ENTER AGAIN TO CONFIRM"});
    } else {
        // Стандартный футер
        drawFooter({"   [Esc]: Cancel    [Enter]: Confirm"});
    }

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_center);
    displaySprite.drawString("Remove this?", SCREEN_WIDTH / 2, 60, &fonts::Font4);

    displaySprite.setTextColor(UI_DANGER);
    displaySprite.drawString("This action is permanent.", SCREEN_WIDTH / 2, 90, &fonts::Font2);
}

// --- ОБРАБОТЧИКИ ЭКРАНОВ ---
void handleSplash(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Any key
    if (isChange && !(kState.opt || kState.ctrl)) {
        playKeyboardSound(kChar, kState);
        switchExternalState(kState.enter ? STATE_VAULT_AUTH : STATE_GUIDE);
    }
}

void handleGuide(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        if (!internalState.isVaultAuthorized) {
            // Если ещё не вошли — на экран логина
            switchExternalState(STATE_VAULT_AUTH);
        } else if (!internalState.isTimeConfigured) {
            // Если вошли, но время не настроено — на установку времени
            switchExternalState(STATE_TIME_CONFIG);
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
    if (kChar == ';') {
        playKeyboardSound(kChar, kState);
        internalState.Guide_ScrollY = max(0, internalState.Guide_ScrollY - step);
    }
    // Down
    else if (kChar == '.') {
        playKeyboardSound(kChar, kState);
        internalState.Guide_ScrollY = min(maxScrollY, internalState.Guide_ScrollY + step);
    }
    // Left
    else if (kChar == ',') {
        playKeyboardSound(kChar, kState);
        internalState.Guide_ScrollX = max(0, internalState.Guide_ScrollX - step);
    }
    // Right
    else if (kChar == '/') {
        playKeyboardSound(kChar, kState);
        internalState.Guide_ScrollX = min(maxScrollX, internalState.Guide_ScrollX + step);
    }

    internalState.requiresRedraw = true;
}

void handleVaultAuth(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    int &pos = internalState.VaultAuth_CursorPosition;
    int len = internalState.VaultAuth_PasswordInput.length();

    // Fn+Esc
    if (isChange && kState.fn && kChar == '`') {
        playKeyboardSound(kChar, kState);
        switchExternalState(STATE_GUIDE);
        return;
    }
    // Fn+Up
    if (kState.fn && kChar == ';') {
        playKeyboardSound(kChar, kState);
        pos = max(0, pos - 10);
        return;
    }
    // Fn+Down
    if (kState.fn && kChar == '.') {
        playKeyboardSound(kChar, kState);
        pos = min(len, pos + 10);
        return;
    }
    // Fn+Left
    if (kState.fn && kChar == ',') {
        playKeyboardSound(kChar, kState);
        if (pos > 0) pos--;
        return;
    }
    // Fn+Right
    if (kState.fn && kChar == '/') {
        playKeyboardSound(kChar, kState);
        if (pos < len) pos++;
        return;
    }
    // Tab
    if (isChange && kState.tab) {
        playKeyboardSound(kChar, kState);
        internalState.VaultAuth_IsPasswordVisible = !internalState.VaultAuth_IsPasswordVisible;
        internalState.requiresRedraw = true;
        return;
    }
    if (kState.del) {
        playKeyboardSound(kChar, kState);
        // Delete
        if (kState.fn) {
            if (pos < len) internalState.VaultAuth_PasswordInput.remove(pos, 1);
        }
        // Backspace
        else {
            if (pos > 0) {
                internalState.VaultAuth_PasswordInput.remove(pos - 1, 1);
                pos--;
            }
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Any other key
    if (kChar >= 32 && kChar <= 126) {
        playKeyboardSound(kChar, kState);
        String left = internalState.VaultAuth_PasswordInput.substring(0, pos);
        String right = internalState.VaultAuth_PasswordInput.substring(pos);
        internalState.VaultAuth_PasswordInput = left + kChar + right;
        pos++;
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        // Проверка существания файла
        bool isNewVault = !SD.exists(DATA_FILE_PATH);

        if (isNewVault || loadDataFromStorage()) {
            // Если файла нет, создаем по умолчанию
            if (isNewVault) saveDataToStorage();
            // Успешная аутентификация
            internalState.isVaultAuthorized = true;
            switchExternalState(internalState.isTimeConfigured ? STATE_ACCOUNT_LIST : STATE_TIME_CONFIG);
        } else {
            // Cообщение о неправильном пароле
            drawMessage({"WRONG", "PASSWORD"}, UI_FG, UI_DANGER);
            delay(600);
            internalState.requiresRedraw = true;
        }
        return;
    }
}

void handleTimeConfig(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        if (internalState.isTimeConfigured) switchExternalState(STATE_SETTINGS_MENU);
        else switchExternalState(STATE_GUIDE);
        return;
    }

    // Если идет синхронизация, блокируем дальнейший ввод
    if (WiFi.scanComplete() != WIFI_SCAN_FAILED) return;

    // Any digit key
    if (isdigit(kChar) && internalState.TimeConfig_TimeInput.length() < 14 && isNextDateTimeDigitValid(internalState.TimeConfig_TimeInput, kChar)) {
        playKeyboardSound(kChar, kState);
        internalState.TimeConfig_TimeInput += kChar;
        internalState.requiresRedraw = true;
        return;
    }
    // Backspace
    if (kState.del && internalState.TimeConfig_TimeInput.length() > 0) {
        playKeyboardSound(kChar, kState);
        internalState.TimeConfig_TimeInput.remove(internalState.TimeConfig_TimeInput.length() - 1);
        internalState.requiresRedraw = true;
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',') {
        playKeyboardSound(kChar, kState);
        internalState.TimeConfig_UTCOffsetInput = min(14, internalState.TimeConfig_UTCOffsetInput + 1);
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/') {
        playKeyboardSound(kChar, kState);
        internalState.TimeConfig_UTCOffsetInput = max(-12, internalState.TimeConfig_UTCOffsetInput - 1);
        internalState.requiresRedraw = true;
        return;
    }
    // Tab
    if (isChange && kState.tab) {
        playKeyboardSound(kChar, kState);
        WiFi.mode(WIFI_STA);
        drawMessage({"Scanning...", "Wi-Fi"});
        bool isTimeSynced = false;
        if (WiFi.scanNetworks() > 0) {
            // Перебираем сети
            int totalWiFiNetworksCount = getTotalWiFiNetworksCount();
            for (int i = 0; i < totalWiFiNetworksCount; i++) {
                bool isSaved, isScanned;
                WiFiNetwork *wn = getWiFiNetworkByIndex(i, isSaved, isScanned);

                // Нам нужны только доступные и сохраненные сети.
                // Благодаря сортировке в getWiFiNetworkByIndex, они идут первыми.
                // Если попалась другая - значит нужные сети закончились, выходим из цикла.
                if (!(isSaved && isScanned)) break;

                drawMessage({"Connecting...", wn->ssid});
                WiFi.begin(wn->ssid, wn->password);

                // Ждем подключения
                int timeout = 100; // 10 секунд при delay(100)
                while (WiFi.status() != WL_CONNECTED && timeout > 0) {
                    delay(100);
                    timeout--;
                }

                if (WiFi.status() == WL_CONNECTED) {
                    drawMessage({"Fetching...", "www.timeapi.io"});

                    HTTPClient http;
                    http.begin("https://www.timeapi.io/api/v1/time/current/unix?timezone=UTC");

                    int httpCode = http.GET();
                    if (httpCode == HTTP_CODE_OK) {
                        String payload = http.getString();
                        http.end();
                        WiFi.disconnect();

                        JsonDocument doc;
                        DeserializationError error = deserializeJson(doc, payload);
                        if (!error) {
                            long unixtime = doc["unix_timestamp"];

                            // Установка времени
                            struct timeval tv = {.tv_sec = unixtime, .tv_usec = 0};
                            settimeofday(&tv, NULL);

                            // Применяем оффсет
                            time_t localTime = unixtime + (internalState.TimeConfig_UTCOffsetInput * 3600);

                            // Получаем структуру разбитого времени
                            struct tm timeinfo;
                            gmtime_r(&localTime, &timeinfo); // Смещенное время

                            // Форматируем строки для сообщения
                            char dateBuf[12]; // YYYY-MM-DD\0
                            char timeBuf[10]; // HH-MM-SS\0
                            sprintf(dateBuf, "%04d-%02d-%02d", timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday);
                            sprintf(timeBuf, "%02d:%02d:%02d", timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);

                            drawMessage({dateBuf, timeBuf}, UI_VALID);
                            delay(800);

                            char sysTimeBuf[15]; // YYYYMMDDHHMMSS\0
                            sprintf(sysTimeBuf, "%04d%02d%02d%02d%02d%02d",
                                timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                                timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);

                            systemPreferences.putString("TA/time", String(sysTimeBuf));
                            systemPreferences.putInt("TA/utc", internalState.TimeConfig_UTCOffsetInput);

                            isTimeSynced = true;
                            break; // Выходим из цикла сетей - время получено и сохранено!

                        } else {
                            drawMessage({"JSON Error", error.c_str()}, UI_DANGER);
                            delay(1000);
                        }
                    } else {
                        http.end();
                        WiFi.disconnect();

                        drawMessage({"HTTP Error", (String)httpCode}, UI_DANGER);
                        delay(1000);
                    }
                } else {
                    WiFi.disconnect();

                    drawMessage({"Connection failed!"}, UI_FG, UI_DANGER);
                    delay(600);
                }
            }
            if (!isTimeSynced) {
                drawMessage({"Time sync", "failed!"}, UI_FG, UI_WARNING);
                delay(1500);
            }
        } else {
            drawMessage({"No Wi-Fi", "O_O"}, UI_FG, UI_WARNING);
            delay(1500);
        }

        // Очистка результатов сканирования и выключение Wi-Fi
        WiFi.scanDelete();
        WiFi.mode(WIFI_OFF);

        if (!isTimeSynced) {
            switchExternalState(STATE_TIME_CONFIG);
        } else if (internalState.isTimeConfigured) {
            switchExternalState(STATE_SETTINGS_MENU);
        } else {
            internalState.isTimeConfigured = true;
            switchExternalState(STATE_ACCOUNT_LIST);
        }
        return;
    }

    // Enter
    if (isChange && kState.enter && internalState.TimeConfig_TimeInput.length() == 14) {
        playKeyboardSound(kChar, kState);
        systemPreferences.putString("TA/time", internalState.TimeConfig_TimeInput);
        systemPreferences.putInt("TA/utc", internalState.TimeConfig_UTCOffsetInput);

        setenv("TZ", "UTC0", 1);
        tzset();
        struct tm t = {0};
        t.tm_year = internalState.TimeConfig_TimeInput.substring(0, 4).toInt() - 1900;
        t.tm_mon = internalState.TimeConfig_TimeInput.substring(4, 6).toInt() - 1;
        t.tm_mday = internalState.TimeConfig_TimeInput.substring(6, 8).toInt();
        t.tm_hour = internalState.TimeConfig_TimeInput.substring(8, 10).toInt();
        t.tm_min = internalState.TimeConfig_TimeInput.substring(10, 12).toInt();
        t.tm_sec = internalState.TimeConfig_TimeInput.substring(12, 14).toInt();
        t.tm_isdst = -1;

        time_t epoch = mktime(&t) - (internalState.TimeConfig_UTCOffsetInput * 3600);
        timeval tv = {.tv_sec = epoch};
        settimeofday(&tv, NULL);

        char tzBuffer[20];
        sprintf(tzBuffer, "GMT%s%d", (internalState.TimeConfig_UTCOffsetInput >= 0 ? "-" : "+"), abs(internalState.TimeConfig_UTCOffsetInput));
        setenv("TZ", tzBuffer, 1);
        tzset();

        if (internalState.isTimeConfigured) switchExternalState(STATE_SETTINGS_MENU);
        else {
            internalState.isTimeConfigured = true;
            switchExternalState(STATE_ACCOUNT_LIST);
        }
        return;
    }
}

void handleSettingsMenu(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        switchExternalState(STATE_GUIDE);
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',') {
        playKeyboardSound(kChar, kState);
        if (internalState.SettingsMenu_SelectedIndex > 0) {
            internalState.SettingsMenu_SelectedIndex--;
        } else {
            // Прыжок с первого на последний
            internalState.SettingsMenu_SelectedIndex = settingsMenuOptionsSize - 1;
        }

        // Корректировка скролла в видимой области (4 пункта)
        if (internalState.SettingsMenu_SelectedIndex < internalState.SettingsMenu_ScrollOffset) {
            // Обычный скролл вверх
            internalState.SettingsMenu_ScrollOffset = internalState.SettingsMenu_SelectedIndex;
        } else if (internalState.SettingsMenu_SelectedIndex >= internalState.SettingsMenu_ScrollOffset + 4) {
            // Если перепрыгнули в самый конец, показываем последние 4 элемента
            int newOffset = settingsMenuOptionsSize - 4;
            internalState.SettingsMenu_ScrollOffset = (newOffset > 0) ? newOffset : 0;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/') {
        playKeyboardSound(kChar, kState);
        if (internalState.SettingsMenu_SelectedIndex < settingsMenuOptionsSize - 1) {
            internalState.SettingsMenu_SelectedIndex++;
        } else {
            // Прыжок с последнего на первый
            internalState.SettingsMenu_SelectedIndex = 0;
        }

        // Корректировка скролла в видимой области (4 пункта)
        if (internalState.SettingsMenu_SelectedIndex >= internalState.SettingsMenu_ScrollOffset + 4) {
            // Обычный скролл вниз
            internalState.SettingsMenu_ScrollOffset = internalState.SettingsMenu_SelectedIndex - 3;
        } else if (internalState.SettingsMenu_SelectedIndex < internalState.SettingsMenu_ScrollOffset) {
            // Если перепрыгнули в самое начало, сбрасываем смещение
            internalState.SettingsMenu_ScrollOffset = 0;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        settingsMenuOptions[internalState.SettingsMenu_SelectedIndex].action();
        return;
    }
}

void handleWiFiConfig(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        // Очистка результатов сканирования
        WiFi.scanDelete();
        // Отключение Wi-Fi
        WiFi.mode(WIFI_OFF);

        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }

    // Для остальных действий ждём окончания сканирования
    if (WiFi.scanComplete() < 0) return;

    // Up or Left
    if (kChar == ';' || kChar == ',') {
        playKeyboardSound(kChar, kState);
        int totalWiFiNetworksCount = getTotalWiFiNetworksCount();
        if (internalState.WiFiConfig_SelectedIndex > 0) internalState.WiFiConfig_SelectedIndex--;
        else internalState.WiFiConfig_SelectedIndex = totalWiFiNetworksCount - 1;

        // Математика для 5 строк
        if (internalState.WiFiConfig_SelectedIndex < internalState.WiFiConfig_ScrollOffset) {
            internalState.WiFiConfig_ScrollOffset = internalState.WiFiConfig_SelectedIndex;
        } else if (internalState.WiFiConfig_SelectedIndex >= internalState.WiFiConfig_ScrollOffset + 5) {
            internalState.WiFiConfig_ScrollOffset = max(0, totalWiFiNetworksCount - 5);
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/') {
        playKeyboardSound(kChar, kState);
        int totalWiFiNetworksCount = getTotalWiFiNetworksCount();
        if (internalState.WiFiConfig_SelectedIndex < totalWiFiNetworksCount - 1) internalState.WiFiConfig_SelectedIndex++;
        else internalState.WiFiConfig_SelectedIndex = 0;

        // Математика для 5 строк
        if (internalState.WiFiConfig_SelectedIndex >= internalState.WiFiConfig_ScrollOffset + 5) {
            internalState.WiFiConfig_ScrollOffset = internalState.WiFiConfig_SelectedIndex - 4;
        } else if (internalState.WiFiConfig_SelectedIndex < internalState.WiFiConfig_ScrollOffset) {
            internalState.WiFiConfig_ScrollOffset = 0;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Del (Backspace)
    if (isChange && kState.del) {
        playKeyboardSound(kChar, kState);
        bool isSaved, isScanned;
        getWiFiNetworkByIndex(internalState.WiFiConfig_SelectedIndex, isSaved, isScanned);
        if (isSaved) switchExternalState(STATE_WIFI_REMOVAL);
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        switchExternalState(STATE_WIFI_CONNECT);
        return;
    }
}

void handleWiFiConnect(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    int &pos = internalState.WiFiConnect_CursorPosition;
    int len = internalState.WiFiConnect_PasswordInput.length();

    // Fn+Esc
    if (isChange && kState.fn && kChar == '`') {
        playKeyboardSound(kChar, kState);
        switchExternalState(STATE_WIFI_CONFIG);
        return;
    }
    // Fn+Up
    if (kState.fn && kChar == ';') {
        playKeyboardSound(kChar, kState);
        pos = max(0, pos - 10);
        return;
    }
    // Fn+Down
    if (kState.fn && kChar == '.') {
        playKeyboardSound(kChar, kState);
        pos = min(len, pos + 10);
        return;
    }
    // Fn+Left
    if (kState.fn && kChar == ',') {
        playKeyboardSound(kChar, kState);
        if (pos > 0) pos--;
        return;
    }
    // Fn+Right
    if (kState.fn && kChar == '/') {
        playKeyboardSound(kChar, kState);
        if (pos < len) pos++;
        return;
    }
    // Tab
    if (isChange && kState.tab) {
        playKeyboardSound(kChar, kState);
        internalState.WiFiConnect_IsPasswordVisible = !internalState.WiFiConnect_IsPasswordVisible;
        internalState.requiresRedraw = true;
        return;
    }
    // Delete, Backspace
    if (kState.del) {
        playKeyboardSound(kChar, kState);
        if (kState.fn) {
            if (pos < len) internalState.WiFiConnect_PasswordInput.remove(pos, 1);
        } else {
            if (pos > 0) {
                internalState.WiFiConnect_PasswordInput.remove(pos - 1, 1);
                pos--;
            }
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Character input
    if (kChar >= 32 && kChar <= 126) {
        playKeyboardSound(kChar, kState);
        String left = internalState.WiFiConnect_PasswordInput.substring(0, pos);
        String right = internalState.WiFiConnect_PasswordInput.substring(pos);
        internalState.WiFiConnect_PasswordInput = left + kChar + right;
        pos++;
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        bool isSaved, isScanned;
        WiFiNetwork *wn = getWiFiNetworkByIndex(internalState.WiFiConfig_SelectedIndex, isSaved, isScanned);

        drawMessage({"Connecting...", wn->ssid});
        WiFi.begin(wn->ssid, internalState.WiFiConnect_PasswordInput);

        // Ждем подключения
        int timeout = 20; // 10 секунд при delay(500)
        while (WiFi.status() != WL_CONNECTED && timeout > 0) {
            delay(500);
            timeout--;
        }

        if (WiFi.status() == WL_CONNECTED) {
            // Сохраняем сеть
            if (isSaved) wn->password = internalState.WiFiConnect_PasswordInput;
            else savedWiFiNetworks.push_back(*wn);
            saveDataToStorage();

            drawMessage({"Successful!", "Credentials saved"}, UI_VALID);
            delay(1000);

            switchExternalState(STATE_WIFI_CONFIG);
        } else {
            drawMessage({"Failed!", "Wrong password"}, UI_FG, UI_DANGER);
            delay(1500);
            internalState.requiresRedraw = true;
        }

        WiFi.disconnect();
        return;
    }
}

void handleWiFiRemoval(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        internalState.WiFiRemoval_isPendingConfirmation = false;
        switchExternalState(STATE_WIFI_CONFIG);
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        if (!internalState.WiFiRemoval_isPendingConfirmation) {
            internalState.WiFiRemoval_isPendingConfirmation = true;
            internalState.requiresRedraw = true;
        } else {
            // Удаляем сеть по SSID
            String ssid = getWiFiNetworkByIndex(internalState.WiFiConfig_SelectedIndex)->ssid;
            for (auto i_wn = savedWiFiNetworks.begin(); i_wn != savedWiFiNetworks.end(); ++i_wn) {
                if (i_wn->ssid == ssid) {
                    savedWiFiNetworks.erase(i_wn);
                    break;
                }
            }
            saveDataToStorage();

            drawMessage({"Wi-Fi", "REMOVED"});
            delay(600);

            internalState.WiFiConfig_SelectedIndex = max(0, internalState.WiFiConfig_SelectedIndex - 1);
            internalState.AccountList_ScrollOffset = max(0, internalState.WiFiConfig_SelectedIndex - 2);

            internalState.WiFiRemoval_isPendingConfirmation = false;
            switchExternalState(STATE_WIFI_CONFIG);
        }
    }
}

void handleBrightnessAdjust(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        internalState.BrightnessAdjust_BrightnessCounter = systemPreferences.getInt("TA/brght", DEFAULT_BRIGHTNESS);
        M5.Display.setBrightness(internalState.BrightnessAdjust_BrightnessCounter);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
    // Up or Right
    if (kChar == ';' || kChar == '/') {
        playKeyboardSound(kChar, kState);
        internalState.BrightnessAdjust_BrightnessCounter = min(255, internalState.BrightnessAdjust_BrightnessCounter + 5);
        M5.Display.setBrightness(internalState.BrightnessAdjust_BrightnessCounter); // Предпросмотр
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Left
    if (kChar == '.' || kChar == ',') {
        playKeyboardSound(kChar, kState);
        internalState.BrightnessAdjust_BrightnessCounter = max(0, internalState.BrightnessAdjust_BrightnessCounter - 5);
        M5.Display.setBrightness(internalState.BrightnessAdjust_BrightnessCounter); // Предпросмотр
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        systemPreferences.putInt("TA/brght", internalState.BrightnessAdjust_BrightnessCounter);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
}

void handleVolumeAdjust(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        internalState.VolumeAdjust_VolumeCounter = systemPreferences.getInt("TA/vol", DEFAULT_VOLUME);
        M5.Speaker.setVolume(internalState.VolumeAdjust_VolumeCounter);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
    // Up or Right
    if (kChar == ';' || kChar == '/') {
        internalState.VolumeAdjust_VolumeCounter = min(255, internalState.VolumeAdjust_VolumeCounter + 5);
        M5.Speaker.setVolume(internalState.VolumeAdjust_VolumeCounter); // Предпросмотр

        // Тестовый звук
        if (internalState.VolumeAdjust_VolumeCounter > 0) {
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
        internalState.VolumeAdjust_VolumeCounter = max(0, internalState.VolumeAdjust_VolumeCounter - 5);
        M5.Speaker.setVolume(internalState.VolumeAdjust_VolumeCounter); // Предпросмотр

        // Тестовый звук
        if (internalState.VolumeAdjust_VolumeCounter > 0) {
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
        playKeyboardSound(kChar, kState);
        systemPreferences.putInt("TA/vol", internalState.VolumeAdjust_VolumeCounter);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
}

void handleSoundConfig(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        internalState.SoundConfig_FieldIndex = 0;
        internalState.SoundConfig_ExternalStateSound = systemPreferences.getBool("TA/snd_es", DEFAULT_SOUND_ES);
        internalState.SoundConfig_KeyboardSound = systemPreferences.getInt("TA/snd_kbd", DEFAULT_SOUND_KBD);
        internalState.SoundConfig_TOTPSound = systemPreferences.getInt("TA/snd_totp", DEFAULT_SOUND_TOTP);
        internalState.SoundConfig_ScreenCaptureSound = systemPreferences.getBool("TA/snd_scr", DEFAULT_SOUND_SCR);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
    // Tab
    if (kState.tab) {
        playKeyboardSound(kChar, kState);
        internalState.SoundConfig_FieldIndex = (internalState.SoundConfig_FieldIndex + 1) % 4;
        internalState.requiresRedraw = true;
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',') {
        playKeyboardSound(kChar, kState);
        switch (internalState.SoundConfig_FieldIndex) {
        case 0: // Переходы
            internalState.SoundConfig_ExternalStateSound = !internalState.SoundConfig_ExternalStateSound;
            break;
        case 1: // Клавиатура (назад: 0->2, 2->1, 1->0)
            internalState.SoundConfig_KeyboardSound = (internalState.SoundConfig_KeyboardSound + 2) % 3;
            break;
        case 2: // TOTP (назад: 0->2, 2->1, 1->0)
            internalState.SoundConfig_TOTPSound = (internalState.SoundConfig_TOTPSound + 2) % 3;
            break;
        case 3: // Скриншот
            internalState.SoundConfig_ScreenCaptureSound = !internalState.SoundConfig_ScreenCaptureSound;
            break;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/') {
        playKeyboardSound(kChar, kState);
        switch (internalState.SoundConfig_FieldIndex) {
        case 0: // Переходы
            internalState.SoundConfig_ExternalStateSound = !internalState.SoundConfig_ExternalStateSound;
            break;
        case 1: // Клавиатура (вперед: 0->1, 1->2, 2->0)
            internalState.SoundConfig_KeyboardSound = (internalState.SoundConfig_KeyboardSound + 1) % 3;
            break;
        case 2: // Клавиатура (вперед: 0->1, 1->2, 2->0)
            internalState.SoundConfig_TOTPSound = (internalState.SoundConfig_TOTPSound + 1) % 3;
            break;
        case 3: // Скриншот
            internalState.SoundConfig_ScreenCaptureSound = !internalState.SoundConfig_ScreenCaptureSound;
            break;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        systemPreferences.putBool("TA/snd_es", internalState.SoundConfig_ExternalStateSound);
        systemPreferences.putInt("TA/snd_kbd", internalState.SoundConfig_KeyboardSound);
        systemPreferences.putInt("TA/snd_totp", internalState.SoundConfig_TOTPSound);
        systemPreferences.putBool("TA/snd_scr", internalState.SoundConfig_ScreenCaptureSound);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
}

void handleTimeoutConfig(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        internalState.TimeoutConfig_FieldIndex = 0;
        internalState.TimeoutConfig_ScreenSaver = systemPreferences.getInt("TA/to_ssv", DEFAULT_SCREEN_SAVER);
        internalState.TimeoutConfig_ScreenSaverInput = String(internalState.TimeoutConfig_ScreenSaver / 1000);
        internalState.TimeoutConfig_VaultDeauth = systemPreferences.getInt("TA/to_vda", DEFAULT_VAULT_DEAUTH);
        internalState.TimeoutConfig_VaultDeauthInput = String(internalState.TimeoutConfig_VaultDeauth / 1000);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
    // Tab
    if (kState.tab) {
        playKeyboardSound(kChar, kState);
        internalState.TimeoutConfig_FieldIndex = (internalState.TimeoutConfig_FieldIndex + 1) % 2;
        internalState.requiresRedraw = true;
        return;
    }
    // Delete
    if (kState.del) {
        playKeyboardSound(kChar, kState);
        switch (internalState.TimeoutConfig_FieldIndex) {
        case 0: // Screen saver
            if (internalState.TimeoutConfig_ScreenSaverInput.length() > 0)
                internalState.TimeoutConfig_ScreenSaverInput.remove(internalState.TimeoutConfig_ScreenSaverInput.length() - 1);
            break;
        case 1: // Vault deauth
            if (internalState.TimeoutConfig_VaultDeauthInput.length() > 0)
                internalState.TimeoutConfig_VaultDeauthInput.remove(internalState.TimeoutConfig_VaultDeauthInput.length() - 1);
            break;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Digits
    if (kChar >= '0' && kChar <= '9') {
        playKeyboardSound(kChar, kState);
        switch (internalState.TimeoutConfig_FieldIndex) {
        case 0: // Screen saver
            if (internalState.TimeoutConfig_ScreenSaverInput.length() < 4)
                internalState.TimeoutConfig_ScreenSaverInput += kChar;
            break;
        case 1: // Vault deauth
            if (internalState.TimeoutConfig_VaultDeauthInput.length() < 4)
                internalState.TimeoutConfig_VaultDeauthInput += kChar;
            break;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        if (internalState.TimeoutConfig_ScreenSaverInput.length() == 0 || internalState.TimeoutConfig_VaultDeauthInput.length() == 0) return;

        internalState.TimeoutConfig_FieldIndex = 0;
        // Сохраняем в миллисекундах
        internalState.TimeoutConfig_ScreenSaver = internalState.TimeoutConfig_ScreenSaverInput.toInt() * 1000;
        systemPreferences.putInt("TA/to_ssv", internalState.TimeoutConfig_ScreenSaver);
        internalState.TimeoutConfig_VaultDeauth = internalState.TimeoutConfig_VaultDeauthInput.toInt() * 1000;
        systemPreferences.putInt("TA/to_vda", internalState.TimeoutConfig_VaultDeauth);

        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
}

void handleVaultPasswordChange(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    int &pos = internalState.VaultPasswordChange_CursorPosition;
    int len = internalState.VaultPasswordChange_PasswordInput.length();

    // Fn+Esc
    if (isChange && kState.fn && kChar == '`') {
        playKeyboardSound(kChar, kState);
        // Сброс подтверждения
        internalState.VaultPasswordChange_isPendingConfirmation = false;
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
    // Fn+Up
    if (kState.fn && kChar == ';') {
        playKeyboardSound(kChar, kState);
        pos = max(0, pos - 10);
        return;
    }
    // Fn+Down
    if (kState.fn && kChar == '.') {
        playKeyboardSound(kChar, kState);
        pos = min(len, pos + 10);
        return;
    }
    // Fn+Left
    if (kState.fn && kChar == ',') {
        playKeyboardSound(kChar, kState);
        if (pos > 0) pos--;
        return;
    }
    // Fn+Right
    if (kState.fn && kChar == '/') {
        playKeyboardSound(kChar, kState);
        if (pos < len) pos++;
        return;
    }
    // Tab
    if (isChange && kState.tab) {
        playKeyboardSound(kChar, kState);
        internalState.VaultPasswordChange_IsPasswordVisible = !internalState.VaultPasswordChange_IsPasswordVisible;
        internalState.requiresRedraw = true;
        return;
    }
    if (kState.del) {
        playKeyboardSound(kChar, kState);
        // Delete
        if (kState.fn) {
            if (pos < len) internalState.VaultPasswordChange_PasswordInput.remove(pos, 1);
        }
        // Backspace
        else {
            if (pos > 0) {
                internalState.VaultPasswordChange_PasswordInput.remove(pos - 1, 1);
                pos--;
            }
        }

        // Сброс подтверждения
        internalState.VaultPasswordChange_isPendingConfirmation = false;
        internalState.requiresRedraw = true;
        return;
    }
    // Any other key
    if (kChar >= 32 && kChar <= 126) {
        playKeyboardSound(kChar, kState);
        String left = internalState.VaultPasswordChange_PasswordInput.substring(0, pos);
        String right = internalState.VaultPasswordChange_PasswordInput.substring(pos);
        internalState.VaultPasswordChange_PasswordInput = left + kChar + right;
        pos++;

        // Сброс подтверждения
        internalState.VaultPasswordChange_isPendingConfirmation = false;
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        if (!internalState.VaultPasswordChange_isPendingConfirmation) {
            internalState.VaultPasswordChange_isPendingConfirmation = true;
            internalState.requiresRedraw = true;
        } else {
            performVaultPasswordChange();

            drawMessage({"PASSWORD", "CHANGED"}, UI_FG, UI_WARNING);
            delay(600);

            // Очищаем для будущих вызовов
            internalState.VaultPasswordChange_PasswordInput = "";
            internalState.VaultPasswordChange_IsPasswordVisible = false;
            internalState.VaultPasswordChange_CursorPosition = 0;
            internalState.VaultPasswordChange_ScrollOffset = 0;
            internalState.VaultPasswordChange_isPendingConfirmation = false;

            switchExternalState(STATE_SETTINGS_MENU);
        }
        return;
    }
}

void handleAccountList(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        switchExternalState(STATE_SETTINGS_MENU);
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',') {
        playKeyboardSound(kChar, kState);
        internalState.AccountList_SelectedIndex = (internalState.AccountList_SelectedIndex > 0) ? internalState.AccountList_SelectedIndex - 1 : savedAccounts.size();
        if (internalState.AccountList_SelectedIndex < internalState.AccountList_ScrollOffset) internalState.AccountList_ScrollOffset = internalState.AccountList_SelectedIndex;
        if (internalState.AccountList_SelectedIndex == (int)savedAccounts.size()) internalState.AccountList_ScrollOffset = max(0, (int)savedAccounts.size() - 3);
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/') {
        playKeyboardSound(kChar, kState);
        internalState.AccountList_SelectedIndex++;
        if (internalState.AccountList_SelectedIndex > (int)savedAccounts.size()) {
            internalState.AccountList_SelectedIndex = 0;
            internalState.AccountList_ScrollOffset = 0;
        }
        if (internalState.AccountList_SelectedIndex >= internalState.AccountList_ScrollOffset + 4) internalState.AccountList_ScrollOffset++;
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        if (internalState.AccountList_SelectedIndex == 0) {
            // Переход в состояние с режимом добавления
            internalState.AccountEditor_IsEditMode = false;
            switchExternalState(STATE_ACCOUNT_EDITOR);
        } else {
            switchExternalState(STATE_ACCOUNT_OPTIONS);
        }
        return;
    }
}

void handleAccountOptions(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        switchExternalState(STATE_ACCOUNT_LIST);
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',') {
        playKeyboardSound(kChar, kState);
        if (internalState.AccountOptions_SelectedIndex > 0) {
            internalState.AccountOptions_SelectedIndex--;
        } else {
            // Прыжок с первого на последний
            internalState.AccountOptions_SelectedIndex = actionMenuOptionsSize - 1;
        }

        // Корректировка скролла в видимой области (4 пункта)
        if (internalState.AccountOptions_SelectedIndex < internalState.AccountOptions_ScrollOffset) {
            // Обычный скролл вверх
            internalState.AccountOptions_ScrollOffset = internalState.AccountOptions_SelectedIndex;
        } else if (internalState.AccountOptions_SelectedIndex >= internalState.AccountOptions_ScrollOffset + 4) {
            // Если перепрыгнули в самый конец, показываем последние 4 элемента
            int newOffset = actionMenuOptionsSize - 4;
            internalState.AccountOptions_ScrollOffset = (newOffset > 0) ? newOffset : 0;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/') {
        playKeyboardSound(kChar, kState);
        if (internalState.AccountOptions_SelectedIndex < actionMenuOptionsSize - 1) {
            internalState.AccountOptions_SelectedIndex++;
        } else {
            // Прыжок с последнего на первый
            internalState.AccountOptions_SelectedIndex = 0;
        }

        // Корректировка скролла в видимой области (4 пункта)
        if (internalState.AccountOptions_SelectedIndex >= internalState.AccountOptions_ScrollOffset + 4) {
            // Обычный скролл вниз
            internalState.AccountOptions_ScrollOffset = internalState.AccountOptions_SelectedIndex - 3;
        } else if (internalState.AccountOptions_SelectedIndex < internalState.AccountOptions_ScrollOffset) {
            // Если перепрыгнули в самое начало, сбрасываем смещение
            internalState.AccountOptions_ScrollOffset = 0;
        }
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        actionMenuOptions[internalState.AccountOptions_SelectedIndex].action();
        return;
    }
}

void handleAccountEditor(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        if (internalState.AccountEditor_IsEditMode) {
            internalState.AccountEditor_FieldIndex = 0;
            internalState.AccountEditor_NameInput = "";
            internalState.AccountEditor_KeyInput = "";
            internalState.AccountEditor_AlgoInput = 0;
            internalState.AccountEditor_DigitsInput = 6;
            internalState.AccountEditor_PeriodInput = 30;
            switchExternalState(STATE_ACCOUNT_OPTIONS);
        } else switchExternalState(STATE_ACCOUNT_LIST);
        return;
    }
    // Tab
    if (kState.tab) {
        playKeyboardSound(kChar, kState);
        internalState.AccountEditor_FieldIndex = (internalState.AccountEditor_FieldIndex + 1) % 5;
        internalState.requiresRedraw = true;
        return;
    }

    if (internalState.AccountEditor_FieldIndex < 2) {
        // Delete
        if (kState.del) {
            playKeyboardSound(kChar, kState);
            if (internalState.AccountEditor_FieldIndex == 0 && internalState.AccountEditor_NameInput.length() > 0) {
                internalState.AccountEditor_NameInput.remove(internalState.AccountEditor_NameInput.length() - 1);
            } else if (internalState.AccountEditor_FieldIndex == 1 && internalState.AccountEditor_KeyInput.length() > 0) {
                internalState.AccountEditor_KeyInput.remove(internalState.AccountEditor_KeyInput.length() - 1);
            }
            internalState.requiresRedraw = true;
            return;
        }
        // Any other key
        if (kChar >= 32 && kChar <= 126) {
            playKeyboardSound(kChar, kState);
            if (internalState.AccountEditor_FieldIndex == 0 && internalState.AccountEditor_NameInput.length() < MAX_ACCOUNT_NAME_LENGTH) {
                internalState.AccountEditor_NameInput += kChar;
            } else if (internalState.AccountEditor_FieldIndex == 1 && internalState.AccountEditor_KeyInput.length() < MAX_BASE32_DECODE_LENGTH) {
                char c = toupper(kChar);
                if ((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) internalState.AccountEditor_KeyInput += c;
            }
            internalState.requiresRedraw = true;
            return;
        }
    } else {
        // Up or Left
        if (kChar == ';' || kChar == ',') {
            playKeyboardSound(kChar, kState);
            if (internalState.AccountEditor_FieldIndex == 2) internalState.AccountEditor_AlgoInput = (internalState.AccountEditor_AlgoInput + 2) % 3;
            if (internalState.AccountEditor_FieldIndex == 3) internalState.AccountEditor_DigitsInput = (internalState.AccountEditor_DigitsInput == 6) ? 8 : 6;
            if (internalState.AccountEditor_FieldIndex == 4) internalState.AccountEditor_PeriodInput = (internalState.AccountEditor_PeriodInput == 30) ? 60 : 30;
            internalState.requiresRedraw = true;
            return;
        }
        // Down or Right
        if (kChar == '.' || kChar == '/') {
            playKeyboardSound(kChar, kState);
            if (internalState.AccountEditor_FieldIndex == 2) internalState.AccountEditor_AlgoInput = (internalState.AccountEditor_AlgoInput + 1) % 3;
            if (internalState.AccountEditor_FieldIndex == 3) internalState.AccountEditor_DigitsInput = (internalState.AccountEditor_DigitsInput == 6) ? 8 : 6;
            if (internalState.AccountEditor_FieldIndex == 4) internalState.AccountEditor_PeriodInput = (internalState.AccountEditor_PeriodInput == 30) ? 60 : 30;
            internalState.requiresRedraw = true;
            return;
        }
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);

        internalState.AccountEditor_NameInput.trim();
        internalState.AccountEditor_KeyInput.trim();
        if (internalState.AccountEditor_NameInput.length() == 0 || internalState.AccountEditor_KeyInput.length() == 0) return;

        Account newAcc = {
            internalState.AccountEditor_NameInput,
            internalState.AccountEditor_KeyInput,
            internalState.AccountEditor_AlgoInput,
            internalState.AccountEditor_DigitsInput,
            internalState.AccountEditor_PeriodInput,
        };
        // Если состояние изменения, то вставляем на место
        if (internalState.AccountEditor_IsEditMode) savedAccounts[internalState.AccountList_SelectedIndex - 1] = newAcc;
        // Иначе добавляем новый
        else {
            savedAccounts.push_back(newAcc);
            internalState.AccountList_SelectedIndex = savedAccounts.size();
            internalState.AccountList_ScrollOffset = max(0, internalState.AccountList_SelectedIndex - 3);
        }
        saveDataToStorage();

        drawMessage({"ACCOUNT", "SAVED"});
        delay(400);

        internalState.AccountEditor_FieldIndex = 0;
        internalState.AccountEditor_NameInput = "";
        internalState.AccountEditor_KeyInput = "";
        internalState.AccountEditor_AlgoInput = 0;
        internalState.AccountEditor_DigitsInput = 6;
        internalState.AccountEditor_PeriodInput = 30;
        switchExternalState(internalState.AccountEditor_IsEditMode ? STATE_ACCOUNT_OPTIONS : STATE_ACCOUNT_LIST);

        return;
    }
}

void handleAccountTOTPView(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        switchExternalState(STATE_ACCOUNT_OPTIONS);
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        Account acc = savedAccounts[internalState.AccountList_SelectedIndex - 1];
        String code = generateTOTP(acc.key, acc.algo, acc.digits, acc.period, time(NULL));

        drawMessage({"TYPING", "VIA USB"});

        usbKeyboard.begin();
        for (char c : code) {
            usbKeyboard.write(c);
            delay(10);
        }
        usbKeyboard.end();

        switch (internalState.SoundConfig_TOTPSound) {
        case 0:
            delay(300);
            break;
        case 1:
            playToneTOTP();
            break;
        case 2:
            playMorseTOTP(code);
            break;
        }

        internalState.requiresRedraw = true;
    }
}

void handleAccountQRView(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        switchExternalState(STATE_ACCOUNT_OPTIONS);
    }
}

void handleAccountRemoval(Keyboard_Class::KeysState kState, char kChar, bool isChange) {
    // Esc
    if (isChange && kChar == '`') {
        playKeyboardSound(kChar, kState);
        internalState.AccountRemoval_isPendingConfirmation = false;
        switchExternalState(STATE_ACCOUNT_OPTIONS);
        return;
    }
    // Enter
    if (isChange && kState.enter) {
        playKeyboardSound(kChar, kState);
        if (!internalState.AccountRemoval_isPendingConfirmation) {
            internalState.AccountRemoval_isPendingConfirmation = true;
            internalState.requiresRedraw = true;
        } else {
            int removeIndex = internalState.AccountList_SelectedIndex;
            int targetIdx = removeIndex - 1;
            Account &accToRemove = savedAccounts[targetIdx];

            for (int i = 0; i < accToRemove.name.length(); i++) {
                accToRemove.name[i] = '\0';
            }
            accToRemove.name = "";
            for (int i = 0; i < accToRemove.key.length(); i++) {
                accToRemove.key[i] = '\0';
            }
            accToRemove.key = "";
            savedAccounts.erase(savedAccounts.begin() + targetIdx);

            saveDataToStorage();

            drawMessage({"ACCOUNT", "REMOVED"});
            delay(600);

            // Смещение индекса на предыдущий элемент списка
            internalState.AccountList_SelectedIndex = max(0, removeIndex - 1);
            internalState.AccountList_ScrollOffset = max(0, internalState.AccountList_SelectedIndex - 2);

            internalState.AccountRemoval_isPendingConfirmation = false;
            switchExternalState(STATE_ACCOUNT_LIST);
        }
    }
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

    // Динамическая задержка повторных нажатий
    int keyRepeatDelay;
    switch (internalState.currentExternalState) {
    case STATE_GUIDE:
        keyRepeatDelay = 50;
        break;
    case STATE_BRIGHTNESS_ADJUST:
    case STATE_VOLUME_ADJUST:
        keyRepeatDelay = 170;
        break;
    case STATE_VAULT_AUTH:
    case STATE_TIME_CONFIG:
    case STATE_SETTINGS_MENU:
    case STATE_WIFI_CONFIG:
    case STATE_WIFI_CONNECT:
    case STATE_SOUND_CONFIG:
    case STATE_TIMEOUT_CONFIG:
    case STATE_VAULT_PASSWORD_CHANGE:
    case STATE_ACCOUNT_LIST:
    case STATE_ACCOUNT_OPTIONS:
    case STATE_ACCOUNT_EDITOR:
        keyRepeatDelay = 250;
        break;
    }

    if (isChange || (millis() - internalState.lastKeyPressTime > keyRepeatDelay)) {
        if (internalState.TimeoutConfig_ScreenSaver > 0 && (millis() - internalState.lastKeyPressTime > internalState.TimeoutConfig_ScreenSaver)) {
            // Нажатие для включения экрана не обрабатываем
            internalState.lastKeyPressTime = millis();
            return;
        }
        internalState.lastKeyPressTime = millis();

        switch (internalState.currentExternalState) {
        case STATE_SPLASH:
            handleSplash(kState, kChar, isChange);
            break;
        case STATE_GUIDE:
            handleGuide(kState, kChar, isChange);
            break;
        case STATE_VAULT_AUTH:
            handleVaultAuth(kState, kChar, isChange);
            break;
        case STATE_TIME_CONFIG:
            handleTimeConfig(kState, kChar, isChange);
            break;
        case STATE_SETTINGS_MENU:
            handleSettingsMenu(kState, kChar, isChange);
            break;
        case STATE_WIFI_CONFIG:
            handleWiFiConfig(kState, kChar, isChange);
            break;
        case STATE_WIFI_CONNECT:
            handleWiFiConnect(kState, kChar, isChange);
            break;
        case STATE_WIFI_REMOVAL:
            handleWiFiRemoval(kState, kChar, isChange);
            break;
        case STATE_BRIGHTNESS_ADJUST:
            handleBrightnessAdjust(kState, kChar, isChange);
            break;
        case STATE_VOLUME_ADJUST:
            handleVolumeAdjust(kState, kChar, isChange);
            break;
        case STATE_SOUND_CONFIG:
            handleSoundConfig(kState, kChar, isChange);
            break;
        case STATE_TIMEOUT_CONFIG:
            handleTimeoutConfig(kState, kChar, isChange);
            break;
        case STATE_VAULT_PASSWORD_CHANGE:
            handleVaultPasswordChange(kState, kChar, isChange);
            break;
        case STATE_ACCOUNT_LIST:
            handleAccountList(kState, kChar, isChange);
            break;
        case STATE_ACCOUNT_EDITOR:
            handleAccountEditor(kState, kChar, isChange);
            break;
        case STATE_ACCOUNT_OPTIONS:
            handleAccountOptions(kState, kChar, isChange);
            break;
        case STATE_ACCOUNT_TOTP_VIEW:
            handleAccountTOTPView(kState, kChar, isChange);
            break;
        case STATE_ACCOUNT_QR_VIEW:
            handleAccountQRView(kState, kChar, isChange);
            break;
        case STATE_ACCOUNT_REMOVAL:
            handleAccountRemoval(kState, kChar, isChange);
            break;
        }
    }
}

// --- ГЛАВНЫЙ ОТРИСОВЩИК ЭКРАНА ---
void processUserInterface() {
    if (!internalState.requiresRedraw) return;
    displaySprite.clearClipRect();

    switch (internalState.currentExternalState) {
    case STATE_SPLASH:
        renderSplash();
        break;
    case STATE_GUIDE:
        renderGuide();
        break;
    case STATE_VAULT_AUTH:
        renderVaultAuth();
        break;
    case STATE_TIME_CONFIG:
        renderTimeConfig();
        break;
    case STATE_SETTINGS_MENU:
        renderSettingsMenu();
        break;
    case STATE_WIFI_CONFIG:
        renderWiFiConfig();
        break;
    case STATE_WIFI_CONNECT:
        renderWiFiConnect();
        break;
    case STATE_WIFI_REMOVAL:
        renderWiFiRemoval();
        break;
    case STATE_BRIGHTNESS_ADJUST:
        renderBrightnessAdjust();
        break;
    case STATE_VOLUME_ADJUST:
        renderVolumeAdjust();
        break;
    case STATE_SOUND_CONFIG:
        renderSoundConfig();
        break;
    case STATE_TIMEOUT_CONFIG:
        renderTimeoutConfig();
        break;
    case STATE_VAULT_PASSWORD_CHANGE:
        renderVaultPasswordChange();
        break;
    case STATE_ACCOUNT_LIST:
        renderAccountList();
        break;
    case STATE_ACCOUNT_EDITOR:
        renderAccountEditor();
        break;
    case STATE_ACCOUNT_OPTIONS:
        renderAccountOptions();
        break;
    case STATE_ACCOUNT_TOTP_VIEW:
        renderAccountTOTP();
        break;
    case STATE_ACCOUNT_QR_VIEW:
        renderAccountQR();
        break;
    case STATE_ACCOUNT_REMOVAL:
        renderAccountRemoval();
        break;
    }

    displaySprite.pushSprite(0, 0);
    internalState.requiresRedraw = false;
}

// --- ОБРАБОТЧИКИ СКРИНШОТОВ ---
void saveScreenBMP(const char *filePath) {
    // Запись файла
    File file = SD.open(filePath, FILE_WRITE);
    if (!file) return;

    // Заголовок BMP для SCREEN_WIDTHxSCREEN_HEIGHT (24 бита)
    static const uint32_t fileSize = 54 + (SCREEN_WIDTH * SCREEN_HEIGHT * 3);
    static const uint8_t header[54] = {
        'B', 'M',
        (uint8_t)(fileSize), (uint8_t)(fileSize >> 8), (uint8_t)(fileSize >> 16), (uint8_t)(fileSize >> 24),
        0, 0, 0, 0, 54, 0, 0, 0,
        40, 0, 0, 0,
        (uint8_t)(SCREEN_WIDTH), (uint8_t)(SCREEN_WIDTH >> 8), 0, 0,
        (uint8_t)(SCREEN_HEIGHT), (uint8_t)(SCREEN_HEIGHT >> 8), 0, 0,
        1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    file.write(header, 54);

    static uint8_t lineBuffer[SCREEN_WIDTH * 3];
    // BMP хранит данные снизу вверх
    for (int y = SCREEN_HEIGHT - 1; y >= 0; y--) {
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
}

void takeScreenshot() {
    // Инициализация индекса файла при первом вызове
    static int nextFileIndex = -1;
    if (nextFileIndex == -1) {
        ensureDirectoryExists(SCREEN_CAPTURE_DIR_PATH);
        File scrDir = SD.open(SCREEN_CAPTURE_DIR_PATH);
        File scrFile = scrDir.openNextFile();

        int maxIndex = -1;
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
        nextFileIndex = maxIndex + 1;
    }

    // Формируем имя и путь файла
    char fileName[32];
    snprintf(fileName, sizeof(fileName), "scr_%04d.bmp", nextFileIndex);
    char filePath[128];
    snprintf(filePath, sizeof(filePath), "%s/%s", SCREEN_CAPTURE_DIR_PATH, fileName);

    // Сохранение в файл
    saveScreenBMP(filePath);

    // Инкремент для следующего файла
    nextFileIndex++;

    drawMessage({"SCREENSHOT", "CAPTURED", fileName});
    // Звуковая индикация
    if (internalState.SoundConfig_ScreenCaptureSound) playToneScreenshot();
    delay(600);

    // Принудительное стирание сообщения с экрана
    internalState.requiresRedraw = true;
}

void startScreenRecording() {
    // Инициализация индекса папки при первом вызове
    static int nextDirIndex = -1;
    if (nextDirIndex == -1) {
        ensureDirectoryExists(SCREEN_CAPTURE_DIR_PATH);
        File scrDir = SD.open(SCREEN_CAPTURE_DIR_PATH);
        File scrFile = scrDir.openNextFile();

        int maxIndex = -1;
        while (scrFile) {
            if (scrFile.isDirectory()) {
                // Используем полное имя папки из объекта File
                const char *dirName = scrFile.name();

                // Ищем "rec_" в имени
                const char *found = strstr(dirName, "rec_");
                if (found) {
                    // Смещаем указатель на длину строки "rec_"
                    // И берем число сразу после "rec_"
                    int idx = atoi(found + 4);
                    if (idx > maxIndex) maxIndex = idx;
                }
            }
            scrFile.close();
            scrFile = scrDir.openNextFile();
        }
        scrDir.close();
        nextDirIndex = maxIndex + 1;
    }

    internalState.screenRecordDirIndex = nextDirIndex;

    // Формируем имя и путь папки
    char dirName[32];
    snprintf(dirName, sizeof(dirName), "rec_%04d/", internalState.screenRecordDirIndex);
    char dirPath[128];
    snprintf(dirPath, sizeof(dirPath), "%s/%s", SCREEN_CAPTURE_DIR_PATH, dirName);

    // Создание папки
    ensureDirectoryExists(dirPath);

    // Инкремент для следующей папки
    nextDirIndex++;

    // Статус записи
    internalState.isScreenRecording = true;

    drawMessage({"RECORDING", "STARTED", dirName});
    // Звуковая индикация
    if (internalState.SoundConfig_ScreenCaptureSound) playToneScreenRecordingStart();
    delay(600);

    // Принудительное стирание сообщения с экрана
    internalState.requiresRedraw = true;
    return;
}

void stopScreenRecording() {
    // Статус записи
    internalState.isScreenRecording = false;

    char messageBuffer[32];
    snprintf(messageBuffer, sizeof(messageBuffer), "scr_%04d-%04d.bmp", 0, internalState.screenRecordFileIndex);
    drawMessage({"RECORDING", "FINISHED", messageBuffer});
    internalState.screenRecordFileIndex = 0;

    // Звуковая индикация
    if (internalState.SoundConfig_ScreenCaptureSound) playToneScreenRecordingStop();
    delay(600);

    // Принудительное стирание сообщения с экрана
    internalState.requiresRedraw = true;
    return;
}

void processScreenCaptureEvents() {
    // Если BtnA вообще не нажата — выходим
    if (!M5Cardputer.BtnA.isPressed()) return;

    if (M5Cardputer.Keyboard.isKeyPressed(KEY_LEFT_CTRL)) {
        // Если зажаты BtnA и Ctrl — это скриншот
        takeScreenshot();
        return;
    }
    if (M5Cardputer.Keyboard.isKeyPressed(KEY_OPT)) {
        // Если зажаты BtnA и Opt — это управление записью
        if (internalState.isScreenRecording) stopScreenRecording();
        else startScreenRecording();
        return;
    }
}

// --- ОБРАБОТЧИКИ ФОНОВЫХ ЗАДАЧ ---
void processInternalStateEvents() {
    // Отключение дисплея через N > 0 секунд
    if (internalState.TimeoutConfig_ScreenSaver > 0 && (millis() - internalState.lastKeyPressTime > internalState.TimeoutConfig_ScreenSaver)) {
        if (M5.Display.getBrightness() > 0) {
            M5.Display.sleep(); // Команда заснуть контроллеру дисплея
            M5.Display.setBrightness(0);
        }
    } else {
        if (M5.Display.getBrightness() == 0) {
            M5.Display.setBrightness(internalState.BrightnessAdjust_BrightnessCounter);
            M5.Display.wakeup(); // Команда проснуться контроллеру дисплея
        }
    }

    // Деаутентификация через N > 0 секунд
    if (internalState.TimeoutConfig_VaultDeauth > 0 && (millis() - internalState.lastKeyPressTime > internalState.TimeoutConfig_VaultDeauth) && internalState.isVaultAuthorized) {
        drawMessage({"TIMEOUT", "VAULT LOCKED"});
        delay(600);

        switchExternalState(STATE_VAULT_AUTH);
    }

    // Запись экрана
    if (internalState.isScreenRecording) {
        static ulong lastScreenRecordingTime = 0;
        // Частота кадров 1к/200мс = 5к/с
        if (millis() - lastScreenRecordingTime >= 200) {
            lastScreenRecordingTime = millis();

            // Формируем путь файла
            char filePath[128];
            snprintf(filePath, sizeof(filePath), "%s/rec_%04d/scr_%04d.bmp", SCREEN_CAPTURE_DIR_PATH, internalState.screenRecordDirIndex, internalState.screenRecordFileIndex);

            // Сохранение в файл и инкремент для следующего имени
            saveScreenBMP(filePath);
            internalState.screenRecordFileIndex++;
        }
    }
}

void processExternalStateEvents() {
    switch (internalState.currentExternalState) {
    case STATE_SPLASH:
        // Анимация на экране загрузки
        static ulong lastSplashAnimationTime = 0;
        // Частота кадров 1к/33мс = 30к/с
        if (millis() - lastSplashAnimationTime > 33) {
            lastSplashAnimationTime = millis();
            internalState.requiresRedraw = true;
        }
        break;
    case STATE_VAULT_AUTH:
    case STATE_WIFI_CONNECT:
    case STATE_VAULT_PASSWORD_CHANGE:
        // Мигание курсора на экране
        static ulong lastCursorBlinkTime = 0;
        // Частота мигания 1к/100мс = 10к/с
        if (millis() - lastCursorBlinkTime > 100) {
            lastCursorBlinkTime = millis();
            internalState.requiresRedraw = true;
        }
        break; // Общий для трех
    case STATE_WIFI_CONFIG: {
        // Обновление списка доступных сетей в асинхр режиме WiFi.scanNetworks(true);
        static int lastScanResult = -2;
        int newScanResult = WiFi.scanComplete();
        if (lastScanResult != newScanResult) {
            // drawDebug({(String)lastScanResult, (String)newScanResult});
            lastScanResult = newScanResult;
            if (lastScanResult >= 0) internalState.requiresRedraw = true;
            // else WiFi.scanNetworks();
        }
        break;
    }
    case STATE_VOLUME_ADJUST:
        // Анимация спектра на экране настройки звука
        static ulong lastSpectrumAnimationTime = 0;
        // Частота кадров 1к/16мс = 62.5к/с
        if (millis() - lastSpectrumAnimationTime > 16) {
            lastSpectrumAnimationTime = millis();
            internalState.requiresRedraw = true;
        }
        break;
    case STATE_ACCOUNT_LIST:
        // Обновление данных о заряде батареи
        static ulong lastBatteryCheckTime = 0;
        // Частота опроса 1р/10000мс = 6р/мин
        if (millis() - lastBatteryCheckTime > 10000) {
            internalState.batteryLevel = M5.Power.getBatteryLevel();
            lastBatteryCheckTime = millis();
        }
    case STATE_ACCOUNT_TOTP_VIEW:
        // Обновление данных в реальном времени
        static time_t lastRedrawTime = 0;
        time_t currentEpochTime = time(NULL);
        if (currentEpochTime != lastRedrawTime) {
            lastRedrawTime = currentEpochTime;
            internalState.requiresRedraw = true;
        }
        break; // Общий для двух
    }
}

void setup() {
    M5Cardputer.begin(M5.config(), true);
    M5.Lcd.setRotation(1);
    displaySprite.createSprite(SCREEN_WIDTH, SCREEN_HEIGHT);

    systemPreferences.begin("by_chillyc0de");
    internalState.TimeConfig_TimeInput = systemPreferences.getString("TA/time", MINIMUM_DATE);
    internalState.TimeConfig_UTCOffsetInput = systemPreferences.getInt("TA/utc", DEFAULT_UTC);

    internalState.BrightnessAdjust_BrightnessCounter = systemPreferences.getInt("TA/brght", DEFAULT_BRIGHTNESS);
    M5.Display.setBrightness(internalState.BrightnessAdjust_BrightnessCounter);
    internalState.VolumeAdjust_VolumeCounter = systemPreferences.getInt("TA/vol", DEFAULT_VOLUME);
    M5.Speaker.setVolume(internalState.VolumeAdjust_VolumeCounter);

    internalState.SoundConfig_ExternalStateSound = systemPreferences.getBool("TA/snd_es", DEFAULT_SOUND_ES);
    internalState.SoundConfig_KeyboardSound = systemPreferences.getInt("TA/snd_kbd", DEFAULT_SOUND_KBD);
    internalState.SoundConfig_TOTPSound = systemPreferences.getInt("TA/snd_totp", DEFAULT_SOUND_TOTP);
    internalState.SoundConfig_ScreenCaptureSound = systemPreferences.getBool("TA/snd_scr", DEFAULT_SOUND_SCR);

    internalState.TimeoutConfig_ScreenSaver = systemPreferences.getInt("TA/to_ssv", DEFAULT_SCREEN_SAVER);
    internalState.TimeoutConfig_VaultDeauth = systemPreferences.getInt("TA/to_vda", DEFAULT_VAULT_DEAUTH);

    SPI.begin(40, 39, 14, 12);
    // Проверка наличия SD
    if (!SD.begin(12, SPI, 40000000)) {
        drawMessage({"SD NOT FOUND", {"Insert SD and reboot", &fonts::Font2}});
        while (true) delay(10000);
    }

    USB.begin();

    switchExternalState(STATE_SPLASH);
}

void loop() {
    // Обновление внутренних состояний библиотеки
    M5Cardputer.update();

    // Обработка фоновых событий
    processInternalStateEvents();
    processExternalStateEvents();

    // Захват экрана перед главным обработчиком клавиатуры
    processScreenCaptureEvents();

    // Обработка KB и UI
    processKeyboardEvents();
    processUserInterface();
}