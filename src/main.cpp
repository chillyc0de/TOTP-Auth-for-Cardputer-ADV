#include <Arduino.h>

#include "USB.h"
#include "USBHIDKeyboard.h"
#undef KEY_BACKSPACE
#undef KEY_TAB
#include <M5Cardputer.h>

#include "qrcode.h"
#include <ArduinoJson.h>
#include <FS.h>
#include <Preferences.h>
#include <SD.h>
#include <vector>

#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"

#define MINIMUM_UNIX_TIMESTAMP 1772755200
#define DEFAULT_UTC_OFFSET 3

const String MINIMUM_DATE_STRING = "20260306000000";
const char *DATA_FILE_PATH = "/by_chillyc0de/TOTP_Auth/data";
const char *FIRMWARE_VERSION = "v1.0.0";

const int SCREEN_WIDTH = 240;
const int SCREEN_HEIGHT = 135;
const int MAX_BASE32_DECODE_LENGTH = 128;
const int MAX_ACCOUNT_NAME_LENGTH = 32;

const uint16_t UI_BG = BLACK;
const uint16_t UI_FG = WHITE;
const uint16_t UI_ACCENT = 0xE204;
const uint16_t UI_MUTED = 0x39E7;
const uint16_t UI_DANGER = 0xF800;
const uint16_t UI_VALID = 0x07E0;

const std::vector<String> userGuideLines = {
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
    " * Secret Keys must be Base32",
    "   (A-Z, 2-7 only).",
    " * View: Generate code.",
    " * QR: Display for migration.",
    " * Edit/Delete: Manage vault.",
    "",
    "-------- 3. USB  AUTO-TYPE --------",
    " Connect Cardputer to PC via USB.",
    " In the 'View TOTP' screen,",
    " press [Enter] to auto-type the",
    " code (USB-HID keyboard mode).",
    "",
    "----------- 4. SECURITY -----------",
    " * Vault: AES-256 encrypted.",
    " * File: /by_chillyc0de/TOTP_Auth/data",
    " * NO PASSWORD RECOVERY! If you",
    "   forget it, data is lost.",
    "",
    "------- 5. LICENSE & RIGHTS -------",
    " Provided 'AS IS' under MIT License.",
    " Use at your own risk. The author",
    " is not responsible for lost data",
    " or locked accounts."
};

enum ExternalState
{
    STATE_SPLASH_SCREEN,
    STATE_GUIDE,
    STATE_LOGIN,
    STATE_TIME_SETUP,
    STATE_ACCOUNT_LIST,
    STATE_ACTION_MENU,
    STATE_ADD_EDIT_ACCOUNT,
    STATE_DELETE_ACCOUNT,
    STATE_VIEW_TOTP,
    STATE_VIEW_QR
};

struct InternalState
{
    ExternalState currentExternalState = STATE_SPLASH_SCREEN;
    bool requiresRedraw = true;
    int timeSetupUTCOffsetInput = DEFAULT_UTC_OFFSET;

    uint8_t salt[16];
    bool isSaltInitialized = false;
    bool isLoggedIn = false;

    int accountListSelectedIndex = 0;
    int accountListScrollOffset = 0;
    int actionMenuSelectedIndex = 0;
    int guideScrollY = 0;
    int guideScrollX = 0;
    int loginCursorPosition = 0;
    int loginScrollOffset = 0;

    bool loginShowPassword = false;
    uint32_t loginErrorClearTime = 0;

    String timeSetupTimeInput = "";
    String loginPasswordInput = "";
    String addEditAccountNameInput = "";
    String addEditAccountKeyInput = "";

    bool isEditMode = false;
    uint8_t addEditAccountAlgoInput = 0;
    uint8_t addEditAccountDigitsInput = 6;
    uint8_t addEditAccountPeriodInput = 30;
    uint8_t addEditAccountFieldIdx = 0;
};

struct MessageLine
{
    String text;
    const lgfx::IFont *fontPtr;
    MessageLine(const char *t, const lgfx::IFont *f = &fonts::Font4) : text(t), fontPtr(f) {}
    MessageLine(String t, const lgfx::IFont *f = &fonts::Font4) : text(t), fontPtr(f) {}
};

struct Account
{
    String name;
    String key;
    uint8_t algo;
    uint8_t digits;
    uint8_t period;
};

USBHIDKeyboard usbKeyboard;
LGFX_Sprite displaySprite(&M5.Lcd);
Preferences systemPreferences;

InternalState internalState;
std::vector<Account> savedAccounts;

void switchExternalState(ExternalState externalState)
{
    internalState.currentExternalState = externalState;
    internalState.requiresRedraw = true;

    if (externalState == STATE_TIME_SETUP)
    {
        time_t nowTime = time(NULL);
        if (nowTime < MINIMUM_UNIX_TIMESTAMP)
        {
            internalState.timeSetupTimeInput = systemPreferences.getString("TOTP_Auth/time", MINIMUM_DATE_STRING);
            internalState.timeSetupUTCOffsetInput = systemPreferences.getInt("TOTP_Auth/utc", DEFAULT_UTC_OFFSET);
        }
        else
        {
            time_t localTime = nowTime + (internalState.timeSetupUTCOffsetInput * 3600);
            struct tm *t = gmtime(&localTime);
            char buf[16];
            strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", t);
            internalState.timeSetupTimeInput = String(buf);
        }
    }
}

// --- КРИПТОГРАФИЧЕСКИЕ ФУНКЦИИ ---
void deriveKey(const String &password, const uint8_t *salt, uint8_t *key)
{
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_pkcs5_pbkdf2_hmac(&ctx, (const unsigned char *)password.c_str(), password.length(), salt, 16, 2000, 32, key);
    mbedtls_md_free(&ctx);
}

int decodeBase32String(const char *encodedString, uint8_t *resultBuffer)
{
    int bitBuffer = 0, bitsLeft = 0, byteCount = 0;
    for (const char *ptr = encodedString; *ptr; ++ptr)
    {
        uint8_t c = toupper(*ptr);
        if (isspace(c) || c == '=' || c == '-') continue;

        uint8_t val = (c >= 'A' && c <= 'Z') ? c - 'A' : (c >= '2' && c <= '7') ? c - '2' + 26 :
                                                                                  0xFF;
        if (val == 0xFF) continue;

        bitBuffer = (bitBuffer << 5) | val;
        bitsLeft += 5;
        if (bitsLeft >= 8)
        {
            resultBuffer[byteCount++] = (bitBuffer >> (bitsLeft - 8)) & 0xFF;
            bitsLeft -= 8;
        }
    }
    if (bitsLeft > 0 && byteCount < MAX_BASE32_DECODE_LENGTH) resultBuffer[byteCount++] = (bitBuffer << (8 - bitsLeft)) & 0xFF;
    return byteCount;
}

String generateTOTP(const String &base32Secret, int algo, int digits, int period, time_t now)
{
    uint8_t key[MAX_BASE32_DECODE_LENGTH];
    int keyLen = decodeBase32String(base32Secret.c_str(), key);
    if (keyLen == 0) return "ERROR";

    uint64_t counter = now / period;
    uint8_t counterBytes[8];
    for (int i = 7; i >= 0; i--)
    {
        counterBytes[i] = counter & 0xFF;
        counter >>= 8;
    }

    mbedtls_md_type_t md_type = (algo == 1) ? MBEDTLS_MD_SHA256 : (algo == 2) ? MBEDTLS_MD_SHA512 :
                                                                                MBEDTLS_MD_SHA1;
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
    char format[10], result[10];
    sprintf(format, "%%0%dd", digits);
    sprintf(result, format, otp);
    return String(result);
}

// --- ФУНКЦИИ ДЛЯ ВАЛИДАЦИИ ---
String urlEncode(const String &str)
{
    String encodedString = "";
    char c;
    char code0;
    char code1;
    for (int i = 0; i < str.length(); i++)
    {
        c = str.charAt(i);
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') encodedString += c;
        else
        {
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

bool isNextDateTimeDigitValid(String currentString, char nextDigit)
{
    String potentialString = currentString + nextDigit;
    int length = potentialString.length();
    int position = currentString.length();
    int digitValue = nextDigit - '0';

    if (potentialString < MINIMUM_DATE_STRING.substring(0, length)) return false;
    if (position < 4) return true;
    if (position == 4) return (digitValue == 0 || digitValue == 1);
    if (position == 5) return (currentString[4] - '0' == 0) ? (digitValue >= 1 && digitValue <= 9) : (digitValue >= 0 && digitValue <= 2);
    if (position == 6) return (digitValue > 3) ? false : (potentialString.substring(4, 6).toInt() == 2) ? (digitValue <= 2) :
                                                                                                          true;
    if (position == 7)
    {
        int year = potentialString.substring(0, 4).toInt();
        int month = potentialString.substring(4, 6).toInt();
        int day = potentialString.substring(6, 8).toInt();
        if (day < 1) return false;

        int maxDaysInMonth[] = { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        if (month == 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))) maxDaysInMonth[2] = 29;
        return (day <= maxDaysInMonth[month]);
    }
    if (position == 8) return (digitValue <= 2);
    if (position == 9) return (potentialString.substring(8, 10).toInt() <= 23);
    if (position == 10 || position == 12) return (digitValue <= 5);
    return true;
}

// --- ФУНКЦИИ ДЛЯ РАБОТЫ С ДАННЫМИ И ХРАНИЛИЩЕМ ---
void ensureDirectoryExists(const char *filePath)
{
    String path = String(filePath);
    int lastSlash = path.lastIndexOf('/');
    if (lastSlash != -1)
    {
        String dir = path.substring(0, lastSlash);
        String currentPath = "";
        int start = 0;
        while (start < dir.length())
        {
            int slashIdx = dir.indexOf('/', start + 1);
            if (slashIdx == -1) slashIdx = dir.length();

            currentPath = dir.substring(0, slashIdx);
            if (!SD.exists(currentPath)) SD.mkdir(currentPath);
            start = slashIdx;
        }
    }
}

bool readVaultFromSD(uint8_t *salt, uint8_t *iv, std::vector<uint8_t> &encBuf)
{
    if (!SD.exists(DATA_FILE_PATH)) return false;

    File file = SD.open(DATA_FILE_PATH, FILE_READ);
    if (!file || file.size() < 32)
    {
        if (file) file.close();
        return false;
    }

    file.read(salt, 16);
    file.read(iv, 16);

    size_t encLen = file.size() - 32;
    if (encLen % 16 != 0 || encLen == 0)
    {
        file.close();
        return false;
    }

    encBuf.resize(encLen);
    file.read(encBuf.data(), encLen);
    file.close();
    return true;
}

bool parseVaultJSON(const std::vector<uint8_t> &decBuf)
{
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, (const char *)decBuf.data(), decBuf.size());
    if (error) return false;

    savedAccounts.clear();
    for (JsonObject obj : doc.as<JsonArray>())
    {
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

String serializeVaultJSON()
{
    JsonDocument doc;
    JsonArray arr = doc.to<JsonArray>();
    for (const auto &acc : savedAccounts)
    {
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

bool decryptVault(const std::vector<uint8_t> &encBuf, const uint8_t *salt, const uint8_t *iv, const String &password, std::vector<uint8_t> &decBuf)
{
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
    for (size_t i = encBuf.size() - padLen; i < encBuf.size(); i++)
    {
        if (decBuf[i] != padLen) return false;
    }

    decBuf.resize(encBuf.size() - padLen);
    return true;
}

void encryptVault(const String &jsonStr, const uint8_t *salt, const uint8_t *iv, const String &password, std::vector<uint8_t> &encBuf)
{
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

bool loadAccountsFromStorage()
{
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

void writeVaultToSD(const uint8_t *salt, const uint8_t *iv, const std::vector<uint8_t> &encBuf)
{
    ensureDirectoryExists(DATA_FILE_PATH);

    File file = SD.open(DATA_FILE_PATH, FILE_WRITE);
    if (file)
    {
        file.write(salt, 16);
        file.write(iv, 16);
        file.write(encBuf.data(), encBuf.size());
        file.close();
    }
}

void saveAccountsToStorage()
{
    if (!internalState.isSaltInitialized)
    {
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

// --- ОТРИСОВКА ВСПОМОГАТЕЛЬНЫХ ЭЛЕМЕНТОВ ---
void drawHeader(String title, String rightText = "")
{
    displaySprite.fillRect(0, 0, SCREEN_WIDTH, 24, UI_ACCENT);
    displaySprite.setTextColor(UI_FG);

    if (rightText == "")
    {
        displaySprite.setTextDatum(middle_center);
        displaySprite.drawString(title, SCREEN_WIDTH / 2, 12, &fonts::Font2);
    }
    else
    {
        displaySprite.setTextDatum(middle_left);
        displaySprite.drawString(title, 10, 12, &fonts::Font2);
        displaySprite.setTextDatum(middle_right);
        displaySprite.drawString(rightText, SCREEN_WIDTH - 10, 12, &fonts::Font2);
    }
}

void drawFooter(std::vector<String> lines)
{
    int numLines = lines.size();

    int lineHeight = 12;
    int padding = 6;

    int footerHeight = (numLines * lineHeight) + padding;

    displaySprite.fillRect(0, SCREEN_HEIGHT - footerHeight, SCREEN_WIDTH, footerHeight, UI_MUTED);
    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_left);

    int startY = (SCREEN_HEIGHT - footerHeight) + 9;
    for (int i = 0; i < numLines; i++)
    {
        int yPos = startY + (i * lineHeight);
        displaySprite.drawString(lines[i], 2, yPos, &fonts::Font0);
    }
}

void drawScrollbar(int current, int visible, int total, int yStart, int height)
{
    if (total <= visible) return;
    int barHeight = max(10, (visible * height) / total);
    int maxTop = total - visible;
    int barY = yStart + (current * (height - barHeight)) / maxTop;
    displaySprite.fillRect(SCREEN_WIDTH - 4, yStart, 4, height, UI_BG);
    displaySprite.fillRect(SCREEN_WIDTH - 3, barY, 2, barHeight, UI_ACCENT);
}

void drawMessage(std::vector<MessageLine> lines, uint16_t bgColor = UI_BG, uint16_t fgColor = UI_FG)
{
    int numLines = std::min((int)lines.size(), 3);
    int lineHeight = 30; // Расстояние между центрами строк

    displaySprite.fillSprite(bgColor);
    displaySprite.setTextColor(fgColor);
    displaySprite.setTextDatum(middle_center);

    int startY = (SCREEN_HEIGHT / 2) - ((numLines - 1) * lineHeight / 2);
    for (int i = 0; i < numLines; i++)
    {
        int yPos = startY + (i * lineHeight);
        displaySprite.drawString(lines[i].text, SCREEN_WIDTH / 2, yPos, lines[i].fontPtr);
    }
    displaySprite.pushSprite(0, 0);
    internalState.requiresRedraw = false;
}

// --- ОТРИСОВКА ЭКРАНОВ ---
void renderSplashScreen()
{
    displaySprite.fillSprite(UI_BG);
    drawFooter({ "    [Any]: Guide      [Enter]: Login" });

    // Настройки заголовка
    int titleX = SCREEN_WIDTH / 2;
    int titleY = 30;
    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(top_center);
    displaySprite.drawString("TOTP AUTH", titleX, titleY, &fonts::Font4);

    // Параметры рамки под Font4
    int rectW = 160;
    int rectH = 35;
    int radius = 8;
    displaySprite.drawRoundRect(titleX - (rectW / 2), titleY - 7, rectW, rectH, radius, 0xF800);
    displaySprite.drawRoundRect(titleX - (rectW / 2) - 1, titleY - 8, rectW + 2, rectH + 2, radius, 0xF800);

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
    for (int i = 0; i < 8; i++)
    {
        uint32_t t = millis() + (i * 200); // Тайминг
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
        }
        else if (i < 6) // БОКОВЫЕ ЯЗЫКИ
        {
            lift = anim * 22;
            // Расширение конусом: чем выше (больше anim), тем сильнее уход в сторону
            int side = (i % 2 == 0) ? 1 : -1;
            stepX = side * (s + (anim * 8));
            particleW = s;

            fCol = (anim < 0.4) ? 0xFD20 : 0xF800;
        }
        else // ИСКРЫ И ДЫМ
        {
            lift = anim * 35;
            stepX = (int)(sin(t * 0.01)) * 6;
            particleW = 1;

            if (anim < 0.5) fCol = 0xFA60;
            else fCol = 0x4208; // Дым
        }

        int fX = nozzleX + stepX;
        int fY = py - lift;

        if (anim < 0.9)
        {
            displaySprite.fillRect(fX, fY, particleW, particleW, fCol);

            // ЭФФЕКТ СВЕТОВОГО ПЯТНА
            if (anim < 0.1) displaySprite.fillRect(nozzleX - 1, py, (s * 2), 2, 0xFD20);
        }
    }
}

void renderGuideScreen()
{
    displaySprite.fillSprite(UI_BG);
    drawHeader("GUIDE");
    drawScrollbar(internalState.guideScrollY / 18, (SCREEN_HEIGHT - 44) / 18, userGuideLines.size(), 26, SCREEN_HEIGHT - 44);
    drawFooter({ "    [Esc]: Back    [Arrows]: Scroll" });

    displaySprite.setClipRect(0, 26, SCREEN_WIDTH - 5, SCREEN_HEIGHT - 44);

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(top_left);
    displaySprite.setFont(&fonts::Font2);

    for (size_t i = 0; i < userGuideLines.size(); i++)
    {
        int yPos = 30 + (i * 18) - internalState.guideScrollY;
        if (yPos > -18 && yPos < SCREEN_HEIGHT) displaySprite.drawString(userGuideLines[i], 5 - internalState.guideScrollX, yPos);
    }
    displaySprite.clearClipRect();
}

void renderLoginScreen()
{
    if (internalState.loginErrorClearTime > 0)
    {
        drawMessage({ { "WRONG" }, { "PASSWORD" } }, UI_DANGER);
        delay(400);
        return;
    }

    const int charWidth = 24;
    const int maxCharsPerLine = 10;
    const int linesPerPage = 2;

    // Подготовка отображаемого текста
    String rawDisplay = internalState.loginPasswordInput;
    if (!internalState.loginShowPassword)
    {
        rawDisplay = "";
        for (int i = 0; i < (int)internalState.loginPasswordInput.length(); i++) rawDisplay += "*";
    }

    // Нарезка на строки
    std::vector<String> lines;
    if (rawDisplay.length() == 0) lines.push_back("");
    else
    {
        for (int i = 0; i < (int)rawDisplay.length(); i += maxCharsPerLine)
        {
            lines.push_back(rawDisplay.substring(i, min(i + maxCharsPerLine, (int)rawDisplay.length())));
        }
        // Если курсор на новой строке
        if (internalState.loginCursorPosition > 0 && internalState.loginCursorPosition % maxCharsPerLine == 0 && internalState.loginCursorPosition == (int)internalState.loginPasswordInput.length())
        {
            lines.push_back("");
        }
    }

    // Авто-скролл
    int cursorLineIdx = internalState.loginCursorPosition / maxCharsPerLine;
    if (cursorLineIdx < internalState.loginScrollOffset) internalState.loginScrollOffset = cursorLineIdx;
    if (cursorLineIdx >= internalState.loginScrollOffset + linesPerPage) internalState.loginScrollOffset = cursorLineIdx - (linesPerPage - 1);

    displaySprite.fillSprite(UI_BG);
    drawHeader("LOGIN");
    drawFooter({ " [Tab]: Show/Hide  [FN+Arrows]: Cursor", " [FN+Esc]: Guide   [Enter]: Login" });

    displaySprite.setTextColor(UI_VALID);
    displaySprite.setTextDatum(middle_center);

    // Вычисляем стартовую X-координату для центрирования всего БЛОКА (10 символов)
    int startX = (SCREEN_WIDTH - maxCharsPerLine * charWidth) / 2 + (charWidth / 2);
    for (int i = 0; i < linesPerPage; i++)
    {
        int lineIdx = internalState.loginScrollOffset + i;

        // Фиксированная Y-координата
        int yPos = (SCREEN_HEIGHT / 2 - 18) + (i * 36);

        // Отрисовка текста
        if (lineIdx < (int)lines.size())
        {
            String txt = lines[lineIdx];
            for (int j = 0; j < (int)txt.length(); j++)
            {
                displaySprite.drawString(String(txt[j]), startX + (j * charWidth), yPos, &fonts::Font4);
            }
        }

        // Отрисовка курсора
        if ((millis() % 1000) < 400 && lineIdx == cursorLineIdx)
        {
            int cursorXInLine = internalState.loginCursorPosition % maxCharsPerLine;

            // Сдвигаем курсор на левый край текущей ячейки символа
            int cursorX = startX + (cursorXInLine * charWidth) - (charWidth / 2);

            // Рисуем курсор
            displaySprite.fillRect(cursorX, yPos - 12, 2, 24, UI_ACCENT);
        }
    }
}

void renderTimeSetupScreen()
{
    String dateMask = "____ - __ - __";
    String timeMask = "__ : __ : __";
    for (int i = 0; i < (int)internalState.timeSetupTimeInput.length(); i++)
    {
        if (i < 8)
        {
            int pos = (i < 4) ? i : (i < 6) ? i + 3 :
                                              i + 6;
            dateMask[pos] = internalState.timeSetupTimeInput[i];
        }
        else
        {
            int timeIdx = i - 8;
            int pos = (timeIdx < 2) ? timeIdx : (timeIdx < 4) ? timeIdx + 3 :
                                                                timeIdx + 6;
            timeMask[pos] = internalState.timeSetupTimeInput[i];
        }
    }

    displaySprite.fillSprite(UI_BG);
    String utcString = "UTC" + String(internalState.timeSetupUTCOffsetInput >= 0 ? "+" : "") + String(internalState.timeSetupUTCOffsetInput);
    drawHeader("TIME SETUP", utcString);
    drawFooter({ "[Esc]: Guide [Arrows]: UTC [Enter]: Set" });

    displaySprite.setTextDatum(middle_center);
    displaySprite.setFont(&fonts::Font4);

    displaySprite.setTextColor(internalState.timeSetupTimeInput.length() >= 8 ? UI_VALID : UI_FG);
    displaySprite.drawString(dateMask, SCREEN_WIDTH / 2, 58);

    displaySprite.setTextColor(internalState.timeSetupTimeInput.length() == 14 ? UI_VALID : UI_FG);
    displaySprite.drawString(timeMask, SCREEN_WIDTH / 2, 93);
}

void renderAccountListScreen()
{
    time_t localTime = time(NULL) + (internalState.timeSetupUTCOffsetInput * 3600);
    struct tm *t = gmtime(&localTime);
    char timeStr[24];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", t);

    displaySprite.fillSprite(UI_BG);
    drawHeader(timeStr);
    drawScrollbar(internalState.accountListScrollOffset, 4, savedAccounts.size() + 1, 28, 88);
    drawFooter({ "   [Esc]: Set time  [Enter]: Actions" });

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_left);

    for (int i = 0; i < 4; i++)
    {
        int idx = internalState.accountListScrollOffset + i;
        int yPos = 28 + (i * 22);
        if (idx <= (int)savedAccounts.size())
        {
            bool isSel = (idx == internalState.accountListSelectedIndex);
            displaySprite.fillRect(4, yPos, SCREEN_WIDTH - 12, 20, isSel ? UI_ACCENT : UI_BG);

            String txt = (idx == 0) ? "[Enter]: Add new account" : savedAccounts[idx - 1].name;
            displaySprite.drawString(txt, 12, yPos + 10, &fonts::Font2);
        }
    }
}

void renderAddEditAccountScreen()
{
    const char *algos[] = { "SHA1", "SHA256", "SHA512" };
    String fields[5] = {
        "Name: " + internalState.addEditAccountNameInput,
        "Key: " + internalState.addEditAccountKeyInput,
        "Algo: < " + String(algos[internalState.addEditAccountAlgoInput]) + " >",
        "Digits: < " + String(internalState.addEditAccountDigitsInput) + " >",
        "Period: < " + String(internalState.addEditAccountPeriodInput) + "s >"
    };

    displaySprite.fillSprite(UI_BG);
    drawHeader(internalState.isEditMode ? "EDIT ACCOUNT" : "ADD ACCOUNT");
    drawFooter({ "   [Tab]: Switch    [Arrows]: Change", "   [Esc]: Cancel    [Enter]: Confirm" });

    displaySprite.setTextDatum(top_left);
    displaySprite.setFont(&fonts::Font2);

    for (int i = 0; i < 5; i++)
    {
        displaySprite.setTextColor(internalState.addEditAccountFieldIdx == i ? UI_VALID : UI_FG);
        displaySprite.drawString(fields[i], 10, 26 + (i * 15));
    }
}

void renderActionMenuScreen()
{
    displaySprite.fillSprite(UI_BG);
    drawHeader(savedAccounts[internalState.accountListSelectedIndex - 1].name);
    drawFooter({ "   [Esc]: Back       [Enter]: Select" });

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_center);

    const char *opts[] = { "View TOTP Code", "Show QR Code", "Edit Account", "Delete Account" };
    for (int i = 0; i < 4; i++)
    {
        bool isSel = (i == internalState.actionMenuSelectedIndex);
        displaySprite.fillRect(20, 32 + (i * 20), 200, 18, isSel ? UI_ACCENT : UI_BG);
        displaySprite.drawString(opts[i], SCREEN_WIDTH / 2, 41 + (i * 20), &fonts::Font2);
    }
}

void renderViewTotpScreen()
{
    time_t now = time(NULL);
    auto acc = savedAccounts[internalState.accountListSelectedIndex - 1];
    String code = generateTOTP(acc.key, acc.algo, acc.digits, acc.period, now);

    displaySprite.fillSprite(UI_BG);
    drawHeader(acc.name);
    drawFooter({ "   [Esc]: Back [Enter]: Type via USB" });

    displaySprite.setTextDatum(middle_center);

    if (code == "ERROR")
    {
        displaySprite.setTextColor(UI_DANGER);
        displaySprite.drawString("BAD KEY", SCREEN_WIDTH / 2, 74, &fonts::Font6);
    }
    else
    {
        displaySprite.setTextColor(UI_VALID);
        displaySprite.drawString(acc.digits == 8 ? code.substring(0, 4) + " " + code.substring(4) : code.substring(0, 3) + " " + code.substring(3), SCREEN_WIDTH / 2, 74, &fonts::Font6);
    }

    int secondsLeft = acc.period - (now % acc.period);
    uint16_t barColor = (code == "ERROR") ? UI_MUTED : ((secondsLeft < 5) ? UI_DANGER : UI_VALID);
    displaySprite.fillRect(10, 105, (secondsLeft * 220) / acc.period, 4, barColor);
}

void renderViewQrScreen()
{
    auto acc = savedAccounts[internalState.accountListSelectedIndex - 1];
    const char *algos[] = { "SHA1", "SHA256", "SHA512" };
    String uri = "otpauth://totp/" + urlEncode(acc.name) + "?secret=" + acc.key + "&algorithm=" + algos[acc.algo] + "&digits=" + String(acc.digits) + "&period=" + String(acc.period);

    QRCode qrcode;
    uint8_t qrcodeData[qrcode_getBufferSize(10)];
    qrcode_initText(&qrcode, qrcodeData, 10, 0, uri.c_str());

    int scale = (qrcode.size < 35) ? 3 : 2;
    int size = qrcode.size * scale;
    int offsetX = 10, offsetY = (SCREEN_HEIGHT - size) / 2;
    int txtX = offsetX + size + ((SCREEN_WIDTH - (offsetX + size)) / 2);

    displaySprite.fillSprite(WHITE);
    for (uint8_t y = 0; y < qrcode.size; y++)
    {
        for (uint8_t x = 0; x < qrcode.size; x++)
        {
            if (qrcode_getModule(&qrcode, x, y))
            {
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

void renderDeleteAccountScreen()
{
    displaySprite.fillSprite(UI_BG);
    drawHeader("DELETE ACCOUNT");
    drawFooter({ "   [Esc]: Cancel    [Enter]: Confirm" });

    displaySprite.setTextColor(UI_FG);
    displaySprite.setTextDatum(middle_center);
    displaySprite.drawString(savedAccounts[internalState.accountListSelectedIndex - 1].name, SCREEN_WIDTH / 2, 60, &fonts::Font4);

    displaySprite.setTextColor(UI_DANGER);
    displaySprite.drawString("This action is permanent.", SCREEN_WIDTH / 2, 90, &fonts::Font2);
}

// --- ОБРАБОТЧИКИ ЭКРАНОВ ---
void handleSplashInput(Keyboard_Class::KeysState kState, char kChar, bool isChange)
{
    // Any key
    if (isChange)
    {
        switchExternalState(kState.enter ? STATE_LOGIN : STATE_GUIDE);
    }
}

void handleGuideInput(Keyboard_Class::KeysState kState, char kChar, bool isChange)
{
    // Esc
    if (isChange && kChar == '`')
    {
        switchExternalState(internalState.isLoggedIn ? STATE_TIME_SETUP : STATE_LOGIN);
        return;
    }

    // Расчет вертикального максимума
    int fontHeight = 18; // Высота символа Font0
    int maxScrollY = max(0, (int)(userGuideLines.size() * fontHeight) - 85);

    // Расчет горизонтального максимума
    size_t maxChars = 0;
    for (const auto &line : userGuideLines)
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

void handleLoginInput(Keyboard_Class::KeysState kState, char kChar, bool isChange)
{
    if (internalState.loginErrorClearTime > 0) return;

    int &pos = internalState.loginCursorPosition;
    int len = internalState.loginPasswordInput.length();

    // Сбрасываем фазу мигания курсора при любом действии, чтобы он не исчезал во время печати
    internalState.requiresRedraw = true;

    // Fn+Esc
    if (isChange && kState.fn && kChar == '`')
    {
        switchExternalState(STATE_GUIDE);
        return;
    }
    // Fn+Up
    if (kState.fn && kChar == ';')
    {
        pos = max(0, pos - 10);
        return;
    }
    // Fn+Down
    if (kState.fn && kChar == '.')
    {
        pos = min(len, pos + 10);
        return;
    }
    // Fn+Left
    if (kState.fn && kChar == ',')
    {
        if (pos > 0) pos--;
        return;
    }
    // Fn+Right
    if (kState.fn && kChar == '/')
    {
        if (pos < len) pos++;
        return;
    }
    // Tab
    if (isChange && kState.tab)
    {
        internalState.loginShowPassword = !internalState.loginShowPassword;
        return;
    }
    if (kState.del)
    {
        // Delete
        if (kState.fn)
        {
            if (pos < len) internalState.loginPasswordInput.remove(pos, 1);
        }
        // Backspace
        else
        {
            if (pos > 0)
            {
                internalState.loginPasswordInput.remove(pos - 1, 1);
                pos--;
            }
        }
        return;
    }
    // Any other key
    if (kChar >= 32 && kChar <= 126)
    {
        String left = internalState.loginPasswordInput.substring(0, pos);
        String right = internalState.loginPasswordInput.substring(pos);
        internalState.loginPasswordInput = left + kChar + right;
        pos++;
        return;
    }
    // Enter
    if (isChange && kState.enter)
    {
        if (loadAccountsFromStorage())
        {
            internalState.isLoggedIn = true;
            switchExternalState(STATE_TIME_SETUP);
        }
        else
        {
            // Особое сообщение о неправильном пароле
            internalState.loginErrorClearTime = millis();
        }
        return;
    }
}

void handleTimeSetupInput(Keyboard_Class::KeysState kState, char kChar, bool isChange)
{
    // Esc
    if (isChange && kChar == '`')
    {
        switchExternalState(STATE_GUIDE);
        return;
    }
    // Any digit key
    if (isdigit(kChar))
    {
        if (internalState.timeSetupTimeInput.length() < 14 && isNextDateTimeDigitValid(internalState.timeSetupTimeInput, kChar))
        {
            internalState.timeSetupTimeInput += kChar;
            internalState.requiresRedraw = true;
        }
        return;
    }
    // Backspace
    if (kState.del)
    {
        if (internalState.timeSetupTimeInput.length() > 0)
        {
            internalState.timeSetupTimeInput.remove(internalState.timeSetupTimeInput.length() - 1);
            internalState.requiresRedraw = true;
        }
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',')
    {
        internalState.timeSetupUTCOffsetInput = min(14, internalState.timeSetupUTCOffsetInput + 1);
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/')
    {
        internalState.timeSetupUTCOffsetInput = max(-12, internalState.timeSetupUTCOffsetInput - 1);
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter && internalState.timeSetupTimeInput.length() == 14)
    {
        systemPreferences.putString("TOTP_Auth/time", internalState.timeSetupTimeInput);
        systemPreferences.putInt("TOTP_Auth/utc", internalState.timeSetupUTCOffsetInput);

        setenv("TZ", "UTC0", 1);
        tzset();
        struct tm t = { 0 };
        t.tm_year = internalState.timeSetupTimeInput.substring(0, 4).toInt() - 1900;
        t.tm_mon = internalState.timeSetupTimeInput.substring(4, 6).toInt() - 1;
        t.tm_mday = internalState.timeSetupTimeInput.substring(6, 8).toInt();
        t.tm_hour = internalState.timeSetupTimeInput.substring(8, 10).toInt();
        t.tm_min = internalState.timeSetupTimeInput.substring(10, 12).toInt();
        t.tm_sec = internalState.timeSetupTimeInput.substring(12, 14).toInt();
        t.tm_isdst = -1;

        time_t epoch = mktime(&t) - (internalState.timeSetupUTCOffsetInput * 3600);
        timeval tv = { .tv_sec = epoch };
        settimeofday(&tv, NULL);

        char tzBuffer[20];
        sprintf(tzBuffer, "GMT%s%d", (internalState.timeSetupUTCOffsetInput >= 0 ? "-" : "+"), abs(internalState.timeSetupUTCOffsetInput));
        setenv("TZ", tzBuffer, 1);
        tzset();

        switchExternalState(STATE_ACCOUNT_LIST);
        return;
    }
}

void handleAccountListInput(Keyboard_Class::KeysState kState, char kChar, bool isChange)
{
    // Esc
    if (isChange && kChar == '`')
    {
        switchExternalState(STATE_TIME_SETUP);
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',')
    {
        internalState.accountListSelectedIndex = (internalState.accountListSelectedIndex > 0) ? internalState.accountListSelectedIndex - 1 : savedAccounts.size();
        if (internalState.accountListSelectedIndex < internalState.accountListScrollOffset) internalState.accountListScrollOffset = internalState.accountListSelectedIndex;
        if (internalState.accountListSelectedIndex == (int)savedAccounts.size()) internalState.accountListScrollOffset = max(0, (int)savedAccounts.size() - 3);
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/')
    {
        internalState.accountListSelectedIndex++;
        if (internalState.accountListSelectedIndex > (int)savedAccounts.size())
        {
            internalState.accountListSelectedIndex = 0;
            internalState.accountListScrollOffset = 0;
        }
        if (internalState.accountListSelectedIndex >= internalState.accountListScrollOffset + 4) internalState.accountListScrollOffset++;
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter)
    {
        if (internalState.accountListSelectedIndex == 0)
        {
            internalState.isEditMode = false;
            internalState.addEditAccountNameInput = internalState.addEditAccountKeyInput = "";
            internalState.addEditAccountAlgoInput = 0;
            internalState.addEditAccountDigitsInput = 6;
            internalState.addEditAccountPeriodInput = 30;
            internalState.addEditAccountFieldIdx = 0;
            switchExternalState(STATE_ADD_EDIT_ACCOUNT);
        }
        else
        {
            internalState.actionMenuSelectedIndex = 0;
            switchExternalState(STATE_ACTION_MENU);
        }
        return;
    }
}

void handleActionMenuInput(Keyboard_Class::KeysState kState, char kChar, bool isChange)
{
    // Esc
    if (isChange && kChar == '`')
    {
        switchExternalState(STATE_ACCOUNT_LIST);
        return;
    }
    // Up or Left
    if (kChar == ';' || kChar == ',')
    {
        internalState.actionMenuSelectedIndex = (internalState.actionMenuSelectedIndex > 0) ? internalState.actionMenuSelectedIndex - 1 : 3;
        internalState.requiresRedraw = true;
        return;
    }
    // Down or Right
    if (kChar == '.' || kChar == '/')
    {
        internalState.actionMenuSelectedIndex = (internalState.actionMenuSelectedIndex < 3) ? internalState.actionMenuSelectedIndex + 1 : 0;
        internalState.requiresRedraw = true;
        return;
    }
    // Enter
    if (isChange && kState.enter)
    {
        if (internalState.actionMenuSelectedIndex == 0) switchExternalState(STATE_VIEW_TOTP);
        else if (internalState.actionMenuSelectedIndex == 1) switchExternalState(STATE_VIEW_QR);
        else if (internalState.actionMenuSelectedIndex == 2)
        {
            auto acc = savedAccounts[internalState.accountListSelectedIndex - 1];
            internalState.addEditAccountNameInput = acc.name;
            internalState.addEditAccountKeyInput = acc.key;
            internalState.addEditAccountAlgoInput = acc.algo;
            internalState.addEditAccountDigitsInput = acc.digits;
            internalState.addEditAccountPeriodInput = acc.period;
            internalState.isEditMode = true;
            internalState.addEditAccountFieldIdx = 0;
            switchExternalState(STATE_ADD_EDIT_ACCOUNT);
        }
        else if (internalState.actionMenuSelectedIndex == 3) switchExternalState(STATE_DELETE_ACCOUNT);
        return;
    }
}

void handleAddEditAccountInput(Keyboard_Class::KeysState kState, char kChar, bool isChange)
{
    // Esc
    if (isChange && kChar == '`')
    {
        switchExternalState(internalState.isEditMode ? STATE_ACTION_MENU : STATE_ACCOUNT_LIST);
        return;
    }
    // Tab
    if (kState.tab)
    {
        internalState.addEditAccountFieldIdx = (internalState.addEditAccountFieldIdx + 1) % 5;
        internalState.requiresRedraw = true;
        return;
    }

    if (internalState.addEditAccountFieldIdx < 2)
    {
        // Delete
        if (kState.del)
        {
            if (internalState.addEditAccountFieldIdx == 0 && internalState.addEditAccountNameInput.length() > 0)
            {
                internalState.addEditAccountNameInput.remove(internalState.addEditAccountNameInput.length() - 1);
            }
            else if (internalState.addEditAccountFieldIdx == 1 && internalState.addEditAccountKeyInput.length() > 0)
            {
                internalState.addEditAccountKeyInput.remove(internalState.addEditAccountKeyInput.length() - 1);
            }
            internalState.requiresRedraw = true;
            return;
        }
        // Any other key
        if (kChar >= 32 && kChar <= 126)
        {
            if (internalState.addEditAccountFieldIdx == 0 && internalState.addEditAccountNameInput.length() < MAX_ACCOUNT_NAME_LENGTH)
            {
                internalState.addEditAccountNameInput += kChar;
            }
            else if (internalState.addEditAccountFieldIdx == 1 && internalState.addEditAccountKeyInput.length() < MAX_BASE32_DECODE_LENGTH)
            {
                char c = toupper(kChar);
                if ((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) internalState.addEditAccountKeyInput += c;
            }
            internalState.requiresRedraw = true;
            return;
        }
    }
    else
    {
        // Up or Left
        if (kChar == ';' || kChar == ',')
        {
            if (internalState.addEditAccountFieldIdx == 2) internalState.addEditAccountAlgoInput = (internalState.addEditAccountAlgoInput + 2) % 3;
            if (internalState.addEditAccountFieldIdx == 3) internalState.addEditAccountDigitsInput = (internalState.addEditAccountDigitsInput == 6) ? 8 : 6;
            if (internalState.addEditAccountFieldIdx == 4) internalState.addEditAccountPeriodInput = (internalState.addEditAccountPeriodInput == 30) ? 60 : 30;
            internalState.requiresRedraw = true;
            return;
        }
        // Down or Right
        if (kChar == '.' || kChar == '/')
        {
            if (internalState.addEditAccountFieldIdx == 2) internalState.addEditAccountAlgoInput = (internalState.addEditAccountAlgoInput + 1) % 3;
            if (internalState.addEditAccountFieldIdx == 3) internalState.addEditAccountDigitsInput = (internalState.addEditAccountDigitsInput == 6) ? 8 : 6;
            if (internalState.addEditAccountFieldIdx == 4) internalState.addEditAccountPeriodInput = (internalState.addEditAccountPeriodInput == 30) ? 60 : 30;
            internalState.requiresRedraw = true;
            return;
        }
    }
    // Enter
    if (isChange && kState.enter)
    {
        internalState.addEditAccountNameInput.trim();
        internalState.addEditAccountKeyInput.trim();
        if (internalState.addEditAccountNameInput.length() > 0 && internalState.addEditAccountKeyInput.length() > 0)
        {
            Account newAcc = {
                internalState.addEditAccountNameInput,
                internalState.addEditAccountKeyInput,
                internalState.addEditAccountAlgoInput,
                internalState.addEditAccountDigitsInput,
                internalState.addEditAccountPeriodInput
            };
            if (internalState.isEditMode) savedAccounts[internalState.accountListSelectedIndex - 1] = newAcc;
            else savedAccounts.push_back(newAcc);
            saveAccountsToStorage();

            drawMessage({ "SAVED" });
            delay(400);

            switchExternalState(internalState.isEditMode ? STATE_ACTION_MENU : STATE_ACCOUNT_LIST);
        }
        return;
    }
}

void handleDeleteAccountInput(Keyboard_Class::KeysState kState, char kChar, bool isChange)
{
    // Esc
    if (isChange && kChar == '`')
    {
        switchExternalState(STATE_ACTION_MENU);
        return;
    }
    // Enter
    if (isChange && kState.enter)
    {
        int deletedIndex = internalState.accountListSelectedIndex;
        savedAccounts.erase(savedAccounts.begin() + (deletedIndex - 1));
        saveAccountsToStorage();

        drawMessage({ "DELETED" });
        delay(400);

        // Смещение индекса на предыдущий элемент списка
        internalState.accountListSelectedIndex = max(0, deletedIndex - 1);
        switchExternalState(STATE_ACCOUNT_LIST);
    }
}

void handleViewTotpInput(Keyboard_Class::KeysState kState, char kChar, bool isChange)
{
    // Esc
    if (isChange && kChar == '`')
    {
        switchExternalState(STATE_ACTION_MENU);
        return;
    }
    // Enter
    if (isChange && kState.enter)
    {
        auto acc = savedAccounts[internalState.accountListSelectedIndex - 1];
        String code = generateTOTP(acc.key, acc.algo, acc.digits, acc.period, time(NULL));

        drawMessage({ "TYPING", "VIA USB" });
        for (char c : code)
        {
            usbKeyboard.write(c);
            delay(15);
        }
        delay(400);

        internalState.requiresRedraw = true;
    }
}

void handleViewQrInput(Keyboard_Class::KeysState kState, char kChar, bool isChange)
{
    // Esc
    if (isChange && kChar == '`') switchExternalState(STATE_ACTION_MENU);
}

// --- ГЛАВНЫЙ ОБРАБОТЧИК КЛАВИАТУРЫ ---
void processKeyboardEvents()
{
    // Если нажатая клавиша изменилась
    bool isChange = M5Cardputer.Keyboard.isChange();
    // Если нажата любая клавиша
    bool isPressed = M5Cardputer.Keyboard.isPressed();

    if (!isPressed) return; // Нет нажатия, нечего обрабатывать

    // Модификатор
    auto kState = M5Cardputer.Keyboard.keysState();
    // Символ
    char kChar = kState.word.size() > 0 ? kState.word[0] : 0;

    // Динамическая задержка скролла
    int repeatDelay;
    switch (internalState.currentExternalState)
    {
    case STATE_SPLASH_SCREEN:
    case STATE_GUIDE:
        repeatDelay = 50;
        break;
    case STATE_LOGIN:
    case STATE_TIME_SETUP:
    case STATE_ACCOUNT_LIST:
    case STATE_ACTION_MENU:
    case STATE_ADD_EDIT_ACCOUNT:
    case STATE_DELETE_ACCOUNT:
    case STATE_VIEW_TOTP:
    case STATE_VIEW_QR:
        repeatDelay = 250;
        break;
    }

    static uint32_t lastKeyPressTime = 0;
    if (isChange || (millis() - lastKeyPressTime > repeatDelay))
    {
        lastKeyPressTime = millis();

        switch (internalState.currentExternalState)
        {
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
#include <FS.h>
#include <SD.h>

// Переменная для контроля частоты скриншотов
unsigned long lastScreenshotMillis = 0;

void saveScreenshot()
{
    // 1. Проверка кулдауна (не чаще раза в 2 секунды)
    if (millis() - lastScreenshotMillis < 100) return;

    // 2. Опрос клавиатуры. Делаем скриншот только при зажатой 'S'
    M5Cardputer.update();
    if (!M5Cardputer.BtnA.isPressed()) return; // Теперь реагирует на BtnA

    lastScreenshotMillis = millis();

    // Путь к файлу с уникальным именем на основе millis()
    String path = "/by_chillyc0de/TOTP_Auth/screenshots/scr_" + String(millis()) + ".bmp";

    // Проверка/создание папки
    if (!SD.exists("/by_chillyc0de/TOTP_Auth/screenshots"))
    {
        SD.mkdir("/by_chillyc0de/TOTP_Auth/screenshots");
    }

    File file = SD.open(path, FILE_WRITE);
    if (!file) return;

    // Заголовок BMP (240x135, 24-бит)
    // Высота указана как -135, чтобы изображение не было перевернутым
    uint32_t fileSize = 54 + (240 * 135 * 3);
    uint8_t header[54] = {
        'B', 'M',
        (uint8_t)(fileSize), (uint8_t)(fileSize >> 8), (uint8_t)(fileSize >> 16), (uint8_t)(fileSize >> 24),
        0, 0, 0, 0, 54, 0, 0, 0, 40, 0, 0, 0,
        240, 0, 0, 0,       // Width: 240
        121, 255, 255, 255, // Height: -135 (2's complement для корректного порядка строк)
        1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    file.write(header, 54);

    // Читаем пиксели из спрайта и сохраняем в формате BGR888
    for (int y = 0; y < 135; y++)
    {
        for (int x = 0; x < 240; x++)
        {
            uint16_t color = displaySprite.readPixel(x, y);
            // Преобразование RGB565 в BGR888
            uint8_t b = (color & 0x001F) << 3;
            uint8_t g = (color & 0x07E0) >> 3;
            uint8_t r = (color & 0xF800) >> 8;
            file.write(b);
            file.write(g);
            file.write(r);
        }
    }
    file.close();

    // Короткая визуальная индикация (вспышка яркостью), что скриншот сделан
    M5Cardputer.Display.setBrightness(0);
    delay(20);
    M5Cardputer.Display.setBrightness(100);
}

void renderUserInterface()
{
    if (!internalState.requiresRedraw) return;
    displaySprite.clearClipRect();

    switch (internalState.currentExternalState)
    {
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
    // Делаем скриншот только если SD карта готова
    if (SD.cardSize() > 0)
    {
        saveScreenshot();
    }
    internalState.requiresRedraw = false;
}

void setup()
{
    auto m5Config = M5.config();
    M5Cardputer.begin(m5Config, true);
    M5.Lcd.setRotation(1);
    displaySprite.createSprite(SCREEN_WIDTH, SCREEN_HEIGHT);

    SPI.begin(40, 39, 14, 12);
    // Проверка наличия SD
    if (!SD.begin(12, SPI, 25000000))
    {
        drawMessage({ "SD NOT FOUND", { "Insert SD and reboot", &fonts::Font2 } });
        while (true) delay(10000);
    }

    if (!SD.exists("/by_chillyc0de/TOTP_Auth/screenshots"))
    {
        SD.mkdir("/by_chillyc0de/TOTP_Auth/screenshots");
    }

    USB.begin();
    usbKeyboard.begin();

    systemPreferences.begin("by_chillyc0de");

    switchExternalState(STATE_SPLASH_SCREEN);
}

void loop()
{
    switch (internalState.currentExternalState)
    {
    case STATE_SPLASH_SCREEN:
        // Анимация на экране загрузки
        static uint32_t lastAnimationTime = 0;
        // Частота кадров 1к/33мс = 30к/с
        if (millis() - lastAnimationTime > 33)
        {
            lastAnimationTime = millis();
            internalState.requiresRedraw = true;
        }

        break;
    case STATE_LOGIN:
        // Мигание курсора на экране логина
        static uint32_t lastCursorBlink = 0;
        // Частота мигания 1к/100 мс = 10к/с
        if (millis() - lastCursorBlink > 100)
        {
            lastCursorBlink = millis();
            internalState.requiresRedraw = true;
        }

        // Особое сообщение о неправильном пароле
        if (internalState.loginErrorClearTime > 0 && (millis() - internalState.loginErrorClearTime) > 1500)
        {
            internalState.loginErrorClearTime = 0;
            internalState.requiresRedraw = true;
        }

        break;
    case STATE_ACCOUNT_LIST:
    case STATE_VIEW_TOTP:
        // Обновление данных в реальном времени
        static time_t lastRecordedTime = 0;
        time_t currentEpochTime = time(NULL);
        if (currentEpochTime != lastRecordedTime)
        {
            lastRecordedTime = currentEpochTime;
            internalState.requiresRedraw = true;
        }

        break;
    }

    M5Cardputer.update();

    processKeyboardEvents();
    renderUserInterface();
}