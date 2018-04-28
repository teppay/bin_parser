#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ctypes import *
from bin_parser.pcap import pcap
from argparse import ArgumentParser

class EVDEVPayload(LittleEndianStructure):
    '''
    references
        https://www.kernel.org/doc/Documentation/input/event-codes.txt
        https://reverseengineering.stackexchange.com/questions/9361/find-the-right-layer-header-for-a-corrupt-pcap
        https://github.com/spotify/linux/blob/master/include/linux/input.h
    '''

    __pld_len__ = 24
    _fields_ = (
                ('timestamp_sec', c_uint64),
                ('timestamp_usec', c_uint64),
                ('ev_type', c_uint16),
                ('ev_code', c_uint16),
                ('ev_value', c_uint32),
               )

class EVent:
    def __init__(self, pld):
        self.ev_type = pld.ev_type
        self.ev_code = pld.ev_code
        self.ev_value = pld.ev_value

    def __str__(self):
        return f'(ev_code:{self.ev_type}) not supported'

class EV_SYN(EVent):
    code = ['SYN_REPORT',
           'SYN_CONFIG', 
           'SYN_MY_REPORT']

    def __str__(self):
        return f'EV_SYN:\t{self.code[self.ev_code]}\t{str(self.ev_value)}'

class EV_KEY(EVent):
    code = {0: ['KEY_RESERVED', '<RESERVED>'],
            1: ['KEY_ESC', '<ESC>'],
            2: ['KEY_1', '1'],
            3: ['KEY_2', '2'],
            4: ['KEY_3', '3'],
            5: ['KEY_4', '4'],
            6: ['KEY_5', '5'],
            7: ['KEY_6', '6'],
            8: ['KEY_7', '7'],
            9: ['KEY_8', '8'],
            10: ['KEY_9', '9'],
            11: ['KEY_0', '0'],
            12: ['KEY_MINUS', '<MINUS>'],
            13: ['KEY_EQUAL', '<EQUAL>'],
            14: ['KEY_BACKSPACE', '<BACKSPACE>'],
            15: ['KEY_TAB', '<TAB>'],
            16: ['KEY_Q', 'Q'],
            17: ['KEY_W', 'W'],
            18: ['KEY_E', 'E'],
            19: ['KEY_R', 'R'],
            20: ['KEY_T', 'T'],
            21: ['KEY_Y', 'Y'],
            22: ['KEY_U', 'U'],
            23: ['KEY_I', 'I'],
            24: ['KEY_O', 'O'],
            25: ['KEY_P', 'P'],
            26: ['KEY_LEFTBRACE', '<LEFTBRACE>'],
            27: ['KEY_RIGHTBRACE', '<RIGHTBRACE>'],
            28: ['KEY_ENTER', '<ENTER>'],
            29: ['KEY_LEFTCTRL', '<LEFTCTRL>'],
            30: ['KEY_A', 'A'],
            31: ['KEY_S', 'S'],
            32: ['KEY_D', 'D'],
            33: ['KEY_F', 'F'],
            34: ['KEY_G', 'G'],
            35: ['KEY_H', 'H'],
            36: ['KEY_J', 'J'],
            37: ['KEY_K', 'K'],
            38: ['KEY_L', 'L'],
            39: ['KEY_SEMICOLON', '<SEMICOLON>'],
            40: ['KEY_APOSTROPHE', '<APOSTROPHE>'],
            41: ['KEY_GRAVE', '<GRAVE>'],
            42: ['KEY_LEFTSHIFT', '<LEFTSHIFT>'],
            43: ['KEY_BACKSLASH', '<BACKSLASH>'],
            44: ['KEY_Z', 'Z'],
            45: ['KEY_X', 'X'],
            46: ['KEY_C', 'C'],
            47: ['KEY_V', 'V'],
            48: ['KEY_B', 'B'],
            49: ['KEY_N', 'N'],
            50: ['KEY_M', 'M'],
            51: ['KEY_COMMA', '<COMMA>'],
            52: ['KEY_DOT', '<DOT>'],
            53: ['KEY_SLASH', '<SLASH>'],
            54: ['KEY_RIGHTSHIFT', '<RIGHTSHIFT>'],
            55: ['KEY_KPASTERISK', '<KPASTERISK>'],
            56: ['KEY_LEFTALT', '<LEFTALT>'],
            57: ['KEY_SPACE', '<SPACE>'],
            58: ['KEY_CAPSLOCK', '<CAPSLOCK>'],
            59: ['KEY_F1', '<F1>'],
            60: ['KEY_F2', '<F2>'],
            61: ['KEY_F3', '<F3>'],
            62: ['KEY_F4', '<F4>'],
            63: ['KEY_F5', '<F5>'],
            64: ['KEY_F6', '<F6>'],
            65: ['KEY_F7', '<F7>'],
            66: ['KEY_F8', '<F8>'],
            67: ['KEY_F9', '<F9>'],
            68: ['KEY_F10', '<F10>'],
            69: ['KEY_NUMLOCK', '<NUMLOCK>'],
            70: ['KEY_SCROLLLOCK', '<SCROLLLOCK>'],
            71: ['KEY_KP7', '<KP7>'],
            72: ['KEY_KP8', '<KP8>'],
            73: ['KEY_KP9', '<KP9>'],
            74: ['KEY_KPMINUS', '<KPMINUS>'],
            75: ['KEY_KP4', '<KP4>'],
            76: ['KEY_KP5', '<KP5>'],
            77: ['KEY_KP6', '<KP6>'],
            78: ['KEY_KPPLUS', '<KPPLUS>'],
            79: ['KEY_KP1', '<KP1>'],
            80: ['KEY_KP2', '<KP2>'],
            81: ['KEY_KP3', '<KP3>'],
            82: ['KEY_KP0', '<KP0>'],
            83: ['KEY_KPDOT', '<KPDOT>'],
            85: ['KEY_ZENKAKUHANKAKU', '<ZENKAKUHANKAKU>'],
            86: ['KEY_102ND', '<102ND>'],
            87: ['KEY_F11', '<F11>'],
            88: ['KEY_F12', '<F12>'],
            89: ['KEY_RO', '<RO>'],
            90: ['KEY_KATAKANA', '<KATAKANA>'],
            91: ['KEY_HIRAGANA', '<HIRAGANA>'],
            92: ['KEY_HENKAN', '<HENKAN>'],
            93: ['KEY_KATAKANAHIRAGANA', '<KATAKANAHIRAGANA>'],
            94: ['KEY_MUHENKAN', '<MUHENKAN>'],
            95: ['KEY_KPJPCOMMA', '<KPJPCOMMA>'],
            96: ['KEY_KPENTER', '<KPENTER>'],
            97: ['KEY_RIGHTCTRL', '<RIGHTCTRL>'],
            98: ['KEY_KPSLASH', '<KPSLASH>'],
            99: ['KEY_SYSRQ', '<SYSRQ>'],
            100: ['KEY_RIGHTALT', '<RIGHTALT>'],
            101: ['KEY_LINEFEED', '<LINEFEED>'],
            102: ['KEY_HOME', '<HOME>'],
            103: ['KEY_UP', '<UP>'],
            104: ['KEY_PAGEUP', '<PAGEUP>'],
            105: ['KEY_LEFT', '<LEFT>'],
            106: ['KEY_RIGHT', '<RIGHT>'],
            107: ['KEY_END', '<END>'],
            108: ['KEY_DOWN', '<DOWN>'],
            109: ['KEY_PAGEDOWN', '<PAGEDOWN>'],
            110: ['KEY_INSERT', '<INSERT>'],
            111: ['KEY_DELETE', '<DELETE>'],
            112: ['KEY_MACRO', '<MACRO>'],
            113: ['KEY_MUTE', '<MUTE>'],
            114: ['KEY_VOLUMEDOWN', '<VOLUMEDOWN>'],
            115: ['KEY_VOLUMEUP', '<VOLUMEUP>'],
            116: ['KEY_POWER', '<POWER>'],
            117: ['KEY_KPEQUAL', '<KPEQUAL>'],
            118: ['KEY_KPPLUSMINUS', '<KPPLUSMINUS>'],
            119: ['KEY_PAUSE', '<PAUSE>'],
            120: ['KEY_SCALE', '<SCALE>'],
            121: ['KEY_KPCOMMA', '<KPCOMMA>'],
            122: ['KEY_HANGEUL', '<HANGEUL>'],
            123: ['KEY_HANJA', '<HANJA>'],
            124: ['KEY_YEN', '<YEN>'],
            125: ['KEY_LEFTMETA', '<LEFTMETA>'],
            126: ['KEY_RIGHTMETA', '<RIGHTMETA>'],
            127: ['KEY_COMPOSE', '<COMPOSE>'],
            128: ['KEY_STOP', '<STOP>'],
            129: ['KEY_AGAIN', '<AGAIN>'],
            130: ['KEY_PROPS', '<PROPS>'],
            131: ['KEY_UNDO', '<UNDO>'],
            132: ['KEY_FRONT', '<FRONT>'],
            133: ['KEY_COPY', '<COPY>'],
            134: ['KEY_OPEN', '<OPEN>'],
            135: ['KEY_PASTE', '<PASTE>'],
            136: ['KEY_FIND', '<FIND>'],
            137: ['KEY_CUT', '<CUT>'],
            138: ['KEY_HELP', '<HELP>'],
            139: ['KEY_MENU', '<MENU>'],
            140: ['KEY_CALC', '<CALC>'],
            141: ['KEY_SETUP', '<SETUP>'],
            142: ['KEY_SLEEP', '<SLEEP>'],
            143: ['KEY_WAKEUP', '<WAKEUP>'],
            144: ['KEY_FILE', '<FILE>'],
            145: ['KEY_SENDFILE', '<SENDFILE>'],
            146: ['KEY_DELETEFILE', '<DELETEFILE>'],
            147: ['KEY_XFER', '<XFER>'],
            148: ['KEY_PROG1', '<PROG1>'],
            149: ['KEY_PROG2', '<PROG2>'],
            150: ['KEY_WWW', '<WWW>'],
            151: ['KEY_MSDOS', '<MSDOS>'],
            152: ['KEY_COFFEE', '<COFFEE>'],
            153: ['KEY_DIRECTION', '<DIRECTION>'],
            154: ['KEY_CYCLEWINDOWS', '<CYCLEWINDOWS>'],
            155: ['KEY_MAIL', '<MAIL>'],
            156: ['KEY_BOOKMARKS', '<BOOKMARKS>'],
            157: ['KEY_COMPUTER', '<COMPUTER>'],
            158: ['KEY_BACK', '<BACK>'],
            159: ['KEY_FORWARD', '<FORWARD>'],
            160: ['KEY_CLOSECD', '<CLOSECD>'],
            161: ['KEY_EJECTCD', '<EJECTCD>'],
            162: ['KEY_EJECTCLOSECD', '<EJECTCLOSECD>'],
            163: ['KEY_NEXTSONG', '<NEXTSONG>'],
            164: ['KEY_PLAYPAUSE', '<PLAYPAUSE>'],
            165: ['KEY_PREVIOUSSONG', '<PREVIOUSSONG>'],
            166: ['KEY_STOPCD', '<STOPCD>'],
            167: ['KEY_RECORD', '<RECORD>'],
            168: ['KEY_REWIND', '<REWIND>'],
            169: ['KEY_PHONE', '<PHONE>'],
            170: ['KEY_ISO', '<ISO>'],
            171: ['KEY_CONFIG', '<CONFIG>'],
            172: ['KEY_HOMEPAGE', '<HOMEPAGE>'],
            173: ['KEY_REFRESH', '<REFRESH>'],
            174: ['KEY_EXIT', '<EXIT>'],
            175: ['KEY_MOVE', '<MOVE>'],
            176: ['KEY_EDIT', '<EDIT>'],
            177: ['KEY_SCROLLUP', '<SCROLLUP>'],
            178: ['KEY_SCROLLDOWN', '<SCROLLDOWN>'],
            179: ['KEY_KPLEFTPAREN', '<KPLEFTPAREN>'],
            180: ['KEY_KPRIGHTPAREN', '<KPRIGHTPAREN>'],
            181: ['KEY_NEW', '<NEW>'],
            182: ['KEY_REDO', '<REDO>'],
            183: ['KEY_F13', '<F13>'],
            184: ['KEY_F14', '<F14>'],
            185: ['KEY_F15', '<F15>'],
            186: ['KEY_F16', '<F16>'],
            187: ['KEY_F17', '<F17>'],
            188: ['KEY_F18', '<F18>'],
            189: ['KEY_F19', '<F19>'],
            190: ['KEY_F20', '<F20>'],
            191: ['KEY_F21', '<F21>'],
            192: ['KEY_F22', '<F22>'],
            193: ['KEY_F23', '<F23>'],
            194: ['KEY_F24', '<F24>'],
            200: ['KEY_PLAYCD', '<PLAYCD>'],
            201: ['KEY_PAUSECD', '<PAUSECD>'],
            202: ['KEY_PROG3', '<PROG3>'],
            203: ['KEY_PROG4', '<PROG4>'],
            204: ['KEY_DASHBOARD', '<DASHBOARD>'],
            205: ['KEY_SUSPEND', '<SUSPEND>'],
            206: ['KEY_CLOSE', '<CLOSE>'],
            207: ['KEY_PLAY', '<PLAY>'],
            208: ['KEY_FASTFORWARD', '<FASTFORWARD>'],
            209: ['KEY_BASSBOOST', '<BASSBOOST>'],
            210: ['KEY_PRINT', '<PRINT>'],
            211: ['KEY_HP', '<HP>'],
            212: ['KEY_CAMERA', '<CAMERA>'],
            213: ['KEY_SOUND', '<SOUND>'],
            214: ['KEY_QUESTION', '<QUESTION>'],
            215: ['KEY_EMAIL', '<EMAIL>'],
            216: ['KEY_CHAT', '<CHAT>'],
            217: ['KEY_SEARCH', '<SEARCH>'],
            218: ['KEY_CONNECT', '<CONNECT>'],
            219: ['KEY_FINANCE', '<FINANCE>'],
            220: ['KEY_SPORT', '<SPORT>'],
            221: ['KEY_SHOP', '<SHOP>'],
            222: ['KEY_ALTERASE', '<ALTERASE>'],
            223: ['KEY_CANCEL', '<CANCEL>'],
            224: ['KEY_BRIGHTNESSDOWN', '<BRIGHTNESSDOWN>'],
            225: ['KEY_BRIGHTNESSUP', '<BRIGHTNESSUP>'],
            226: ['KEY_MEDIA', '<MEDIA>'],
            227: ['KEY_SWITCHVIDEOMODE', '<SWITCHVIDEOMODE>'],
            228: ['KEY_KBDILLUMTOGGLE', '<KBDILLUMTOGGLE>'],
            229: ['KEY_KBDILLUMDOWN', '<KBDILLUMDOWN>'],
            230: ['KEY_KBDILLUMUP', '<KBDILLUMUP>'],
            231: ['KEY_SEND', '<SEND>'],
            232: ['KEY_REPLY', '<REPLY>'],
            233: ['KEY_FORWARDMAIL', '<FORWARDMAIL>'],
            234: ['KEY_SAVE', '<SAVE>'],
            235: ['KEY_DOCUMENTS', '<DOCUMENTS>'],
            236: ['KEY_BATTERY', '<BATTERY>'],
            237: ['KEY_BLUETOOTH', '<BLUETOOTH>'],
            238: ['KEY_WLAN', '<WLAN>'],
            239: ['KEY_UWB', '<UWB>'],
            240: ['KEY_UNKNOWN', '<UNKNOWN>'],
            241: ['KEY_VIDEO_NEXT', '<VIDEO_NEXT>'],
            242: ['KEY_VIDEO_PREV', '<VIDEO_PREV>'],
            243: ['KEY_BRIGHTNESS_CYCLE', '<BRIGHTNESS_CYCLE>'],
            244: ['KEY_BRIGHTNESS_ZERO', '<BRIGHTNESS_ZERO>'],
            245: ['KEY_DISPLAY_OFF', '<DISPLAY_OFF>'],
            246: ['KEY_WIMAX', '<WIMAX>'],
            256: ['BTN_0', '0'],
            257: ['BTN_1', '1'],
            258: ['BTN_2', '2'],
            259: ['BTN_3', '3'],
            260: ['BTN_4', '4'],
            261: ['BTN_5', '5'],
            262: ['BTN_6', '6'],
            263: ['BTN_7', '7'],
            264: ['BTN_8', '8'],
            265: ['BTN_9', '9'],
            272: ['BTN_LEFT', '<LEFT>'],
            273: ['BTN_RIGHT', '<RIGHT>'],
            274: ['BTN_MIDDLE', '<MIDDLE>'],
            275: ['BTN_SIDE', '<SIDE>'],
            276: ['BTN_EXTRA', '<EXTRA>'],
            277: ['BTN_FORWARD', '<FORWARD>'],
            278: ['BTN_BACK', '<BACK>'],
            279: ['BTN_TASK', '<TASK>'],
            288: ['BTN_TRIGGER', '<TRIGGER>'],
            289: ['BTN_THUMB', '<THUMB>'],
            290: ['BTN_THUMB2', '<THUMB2>'],
            291: ['BTN_TOP', '<TOP>'],
            292: ['BTN_TOP2', '<TOP2>'],
            293: ['BTN_PINKIE', '<PINKIE>'],
            294: ['BTN_BASE', '<BASE>'],
            295: ['BTN_BASE2', '<BASE2>'],
            296: ['BTN_BASE3', '<BASE3>'],
            297: ['BTN_BASE4', '<BASE4>'],
            298: ['BTN_BASE5', '<BASE5>'],
            299: ['BTN_BASE6', '<BASE6>'],
            303: ['BTN_DEAD', '<DEAD>'],
            304: ['BTN_A', 'A'],
            305: ['BTN_B', 'B'],
            306: ['BTN_C', 'C'],
            307: ['BTN_X', 'X'],
            308: ['BTN_Y', 'Y'],
            309: ['BTN_Z', 'Z'],
            310: ['BTN_TL', '<TL>'],
            311: ['BTN_TR', '<TR>'],
            312: ['BTN_TL2', '<TL2>'],
            313: ['BTN_TR2', '<TR2>'],
            314: ['BTN_SELECT', '<SELECT>'],
            315: ['BTN_START', '<START>'],
            316: ['BTN_MODE', '<MODE>'],
            317: ['BTN_THUMBL', '<THUMBL>'],
            318: ['BTN_THUMBR', '<THUMBR>'],
            320: ['BTN_TOOL_PEN', '<TOOL_PEN>'],
            321: ['BTN_TOOL_RUBBER', '<TOOL_RUBBER>'],
            322: ['BTN_TOOL_BRUSH', '<TOOL_BRUSH>'],
            323: ['BTN_TOOL_PENCIL', '<TOOL_PENCIL>'],
            324: ['BTN_TOOL_AIRBRUSH', '<TOOL_AIRBRUSH>'],
            325: ['BTN_TOOL_FINGER', '<TOOL_FINGER>'],
            326: ['BTN_TOOL_MOUSE', '<TOOL_MOUSE>'],
            327: ['BTN_TOOL_LENS', '<TOOL_LENS>'],
            330: ['BTN_TOUCH', '<TOUCH>'],
            331: ['BTN_STYLUS', '<STYLUS>'],
            332: ['BTN_STYLUS2', '<STYLUS2>'],
            333: ['BTN_TOOL_DOUBLETAP', '<TOOL_DOUBLETAP>'],
            334: ['BTN_TOOL_TRIPLETAP', '<TOOL_TRIPLETAP>'],
            335: ['BTN_TOOL_QUADTAP', '<TOOL_QUADTAP>'],
            336: ['BTN_GEAR_DOWN', '<GEAR_DOWN>'],
            337: ['BTN_GEAR_UP', '<GEAR_UP>'],
            352: ['KEY_OK', '<OK>'],
            353: ['KEY_SELECT', '<SELECT>'],
            354: ['KEY_GOTO', '<GOTO>'],
            355: ['KEY_CLEAR', '<CLEAR>'],
            356: ['KEY_POWER2', '<POWER2>'],
            357: ['KEY_OPTION', '<OPTION>'],
            358: ['KEY_INFO', '<INFO>'],
            359: ['KEY_TIME', '<TIME>'],
            360: ['KEY_VENDOR', '<VENDOR>'],
            361: ['KEY_ARCHIVE', '<ARCHIVE>'],
            362: ['KEY_PROGRAM', '<PROGRAM>'],
            363: ['KEY_CHANNEL', '<CHANNEL>'],
            364: ['KEY_FAVORITES', '<FAVORITES>'],
            365: ['KEY_EPG', '<EPG>'],
            366: ['KEY_PVR', '<PVR>'],
            367: ['KEY_MHP', '<MHP>'],
            368: ['KEY_LANGUAGE', '<LANGUAGE>'],
            369: ['KEY_TITLE', '<TITLE>'],
            370: ['KEY_SUBTITLE', '<SUBTITLE>'],
            371: ['KEY_ANGLE', '<ANGLE>'],
            372: ['KEY_ZOOM', '<ZOOM>'],
            373: ['KEY_MODE', '<MODE>'],
            374: ['KEY_KEYBOARD', '<KEYBOARD>'],
            375: ['KEY_SCREEN', '<SCREEN>'],
            376: ['KEY_PC', '<PC>'],
            377: ['KEY_TV', '<TV>'],
            378: ['KEY_TV2', '<TV2>'],
            379: ['KEY_VCR', '<VCR>'],
            380: ['KEY_VCR2', '<VCR2>'],
            381: ['KEY_SAT', '<SAT>'],
            382: ['KEY_SAT2', '<SAT2>'],
            383: ['KEY_CD', '<CD>'],
            384: ['KEY_TAPE', '<TAPE>'],
            385: ['KEY_RADIO', '<RADIO>'],
            386: ['KEY_TUNER', '<TUNER>'],
            387: ['KEY_PLAYER', '<PLAYER>'],
            388: ['KEY_TEXT', '<TEXT>'],
            389: ['KEY_DVD', '<DVD>'],
            390: ['KEY_AUX', '<AUX>'],
            391: ['KEY_MP3', '<MP3>'],
            392: ['KEY_AUDIO', '<AUDIO>'],
            393: ['KEY_VIDEO', '<VIDEO>'],
            394: ['KEY_DIRECTORY', '<DIRECTORY>'],
            395: ['KEY_LIST', '<LIST>'],
            396: ['KEY_MEMO', '<MEMO>'],
            397: ['KEY_CALENDAR', '<CALENDAR>'],
            398: ['KEY_RED', '<RED>'],
            399: ['KEY_GREEN', '<GREEN>'],
            400: ['KEY_YELLOW', '<YELLOW>'],
            401: ['KEY_BLUE', '<BLUE>'],
            402: ['KEY_CHANNELUP', '<CHANNELUP>'],
            403: ['KEY_CHANNELDOWN', '<CHANNELDOWN>'],
            404: ['KEY_FIRST', '<FIRST>'],
            405: ['KEY_LAST', '<LAST>'],
            406: ['KEY_AB', '<AB>'],
            407: ['KEY_NEXT', '<NEXT>'],
            408: ['KEY_RESTART', '<RESTART>'],
            409: ['KEY_SLOW', '<SLOW>'],
            410: ['KEY_SHUFFLE', '<SHUFFLE>'],
            411: ['KEY_BREAK', '<BREAK>'],
            412: ['KEY_PREVIOUS', '<PREVIOUS>'],
            413: ['KEY_DIGITS', '<DIGITS>'],
            414: ['KEY_TEEN', '<TEEN>'],
            415: ['KEY_TWEN', '<TWEN>'],
            416: ['KEY_VIDEOPHONE', '<VIDEOPHONE>'],
            417: ['KEY_GAMES', '<GAMES>'],
            418: ['KEY_ZOOMIN', '<ZOOMIN>'],
            419: ['KEY_ZOOMOUT', '<ZOOMOUT>'],
            420: ['KEY_ZOOMRESET', '<ZOOMRESET>'],
            421: ['KEY_WORDPROCESSOR', '<WORDPROCESSOR>'],
            422: ['KEY_EDITOR', '<EDITOR>'],
            423: ['KEY_SPREADSHEET', '<SPREADSHEET>'],
            424: ['KEY_GRAPHICSEDITOR', '<GRAPHICSEDITOR>'],
            425: ['KEY_PRESENTATION', '<PRESENTATION>'],
            426: ['KEY_DATABASE', '<DATABASE>'],
            427: ['KEY_NEWS', '<NEWS>'],
            428: ['KEY_VOICEMAIL', '<VOICEMAIL>'],
            429: ['KEY_ADDRESSBOOK', '<ADDRESSBOOK>'],
            430: ['KEY_MESSENGER', '<MESSENGER>'],
            431: ['KEY_DISPLAYTOGGLE', '<DISPLAYTOGGLE>'],
            432: ['KEY_SPELLCHECK', '<SPELLCHECK>'],
            433: ['KEY_LOGOFF', '<LOGOFF>'],
            434: ['KEY_DOLLAR', '<DOLLAR>'],
            435: ['KEY_EURO', '<EURO>'],
            436: ['KEY_FRAMEBACK', '<FRAMEBACK>'],
            437: ['KEY_FRAMEFORWARD', '<FRAMEFORWARD>'],
            438: ['KEY_CONTEXT_MENU', '<CONTEXT_MENU>'],
            439: ['KEY_MEDIA_REPEAT', '<MEDIA_REPEAT>'],
            448: ['KEY_DEL_EOL', '<DEL_EOL>'],
            449: ['KEY_DEL_EOS', '<DEL_EOS>'],
            450: ['KEY_INS_LINE', '<INS_LINE>'],
            451: ['KEY_DEL_LINE', '<DEL_LINE>'],
            464: ['KEY_FN', '<FN>'],
            465: ['KEY_FN_ESC', '<FN_ESC>'],
            466: ['KEY_FN_F1', '<FN_F1>'],
            467: ['KEY_FN_F2', '<FN_F2>'],
            468: ['KEY_FN_F3', '<FN_F3>'],
            469: ['KEY_FN_F4', '<FN_F4>'],
            470: ['KEY_FN_F5', '<FN_F5>'],
            471: ['KEY_FN_F6', '<FN_F6>'],
            472: ['KEY_FN_F7', '<FN_F7>'],
            473: ['KEY_FN_F8', '<FN_F8>'],
            474: ['KEY_FN_F9', '<FN_F9>'],
            475: ['KEY_FN_F10', '<FN_F10>'],
            476: ['KEY_FN_F11', '<FN_F11>'],
            477: ['KEY_FN_F12', '<FN_F12>'],
            478: ['KEY_FN_1', '<FN_1>'],
            479: ['KEY_FN_2', '<FN_2>'],
            480: ['KEY_FN_D', '<FN_D>'],
            481: ['KEY_FN_E', '<FN_E>'],
            482: ['KEY_FN_F', '<FN_F>'],
            483: ['KEY_FN_S', '<FN_S>'],
            484: ['KEY_FN_B', '<FN_B>'],
            497: ['KEY_BRL_DOT1', '<BRL_DOT1>'],
            498: ['KEY_BRL_DOT2', '<BRL_DOT2>'],
            499: ['KEY_BRL_DOT3', '<BRL_DOT3>'],
            500: ['KEY_BRL_DOT4', '<BRL_DOT4>'],
            501: ['KEY_BRL_DOT5', '<BRL_DOT5>'],
            502: ['KEY_BRL_DOT6', '<BRL_DOT6>'],
            503: ['KEY_BRL_DOT7', '<BRL_DOT7>'],
            504: ['KEY_BRL_DOT8', '<BRL_DOT8>'],
            505: ['KEY_BRL_DOT9', '<BRL_DOT9>'],
            506: ['KEY_BRL_DOT10', '<BRL_DOT10>'],
            512: ['KEY_NUMERIC_0', '<NUMERIC_0>'],
            513: ['KEY_NUMERIC_1', '<NUMERIC_1>'],
            514: ['KEY_NUMERIC_2', '<NUMERIC_2>'],
            515: ['KEY_NUMERIC_3', '<NUMERIC_3>'],
            516: ['KEY_NUMERIC_4', '<NUMERIC_4>'],
            517: ['KEY_NUMERIC_5', '<NUMERIC_5>'],
            518: ['KEY_NUMERIC_6', '<NUMERIC_6>'],
            519: ['KEY_NUMERIC_7', '<NUMERIC_7>'],
            520: ['KEY_NUMERIC_8', '<NUMERIC_8>'],
            521: ['KEY_NUMERIC_9', '<NUMERIC_9>'],
            522: ['KEY_NUMERIC_STAR', '<NUMERIC_STAR>'],
            523: ['KEY_NUMERIC_POUND', '<NUMERIC_POUND>'],
            767: ['KEY_MAX', '<MAX>']}
    value = ['push', 'release']
    
    def __str__(self):
        return f'EV_SYN:\t{self.code[self.ev_code][0]}\t{self.ev_value}'

class EV_REL(EVent):
    # TODO
    pass
class EV_ABS(EVent):
    # TODO
    pass
class EV_MSC(EVent):
    # TODO
    pass
class EV_SW(EVent):
    # TODO
    pass
class EV_LED(EVent):
    # TODO
    pass
class EV_SND(EVent):
    # TODO
    pass
class EV_REP(EVent):
    # TODO
    pass
class EV_FF(EVent):
    # TODO
    pass
class EV_PWR(EVent):
    # TODO
    pass
class EV_FF_STATUS(EVent):
    # TODO
    pass
class EV_MAX(EVent):
    # TODO
    pass
class EV_CNT(EVent):
    # TODO
    pass

class Reader:

    EV = [EV_SYN, EV_KEY, EV_REL, EV_ABS, EV_MSC, EV_SW, EV_LED, EV_SND, EV_REP, EV_FF, EV_PWR, EV_FF_STATUS, EV_MAX, EV_CNT]

    def __init__(self, fileobj):
        self.__f = fileobj
        self.__fh = pcap.PcapHeader()
        self.__ph = pcap.PacketHeader()
        self.__pld = EVDEVPayload()
        self.__f.readinto(self.__fh)
    
    def show_events(self):
        for _ in range(500):
            if not self.__f.readable():
                break

            self.__f.readinto(self.__ph)
            self.__f.readinto(self.__pld)
            event = self.EV[self.__pld.ev_type](self.__pld)
            print(event)
            
        self.__f.seek(0)
    


def show_evdev_payload(evdev_payload):
    print(f'timestamp_sec : {evdev_payload.timestamp_sec}')
    print(f'timestamp_usec : {evdev_payload.timestamp_usec}')
    print(f'ev_type : {evdev_payload.ev_type}')
    print(f'ev_code : {evdev_payload.ev_code}')
    print(f'ev_value : {evdev_payload.ev_value}')

def debug():
    file_name = 'kbd.pcap'
    # file_name = 'test.pcap'

    buffer = open(file_name, 'rb')
    r = Reader(buffer)
    r.show_events()

if __name__ == '__main__':
    # Check debug flag
    parser = ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    
    is_debug = args.debug

    if is_debug:
        debug()
