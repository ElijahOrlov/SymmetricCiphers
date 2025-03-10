from common import PKCS7Padding as pkcs7
import argparse, sys, os

class Magma:
    """
    Симметричный блочный алгоритм шифрования "Магма" (ГОСТ Р 34.12-2015)
    (шифрование и расшифрование 64-битных блоков)
    РЕЖИМ: ECB (Electronic Codebook) — каждый блок данных шифруется независимо
    """

    # Таблица замен (S-блок)
    S_BOX = [
        [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
        [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
        [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
        [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
        [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
        [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
        [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
        [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]
    ]

    def __init__(self, key: int):
        """
        Инициализация шифра.
        :param key: 256-битный ключ в виде целого числа
        """
        self.key = key
        # Преобразуем ключ в 32-битные подключи
        self.round_keys = self._prepare_round_keys(key)

    @staticmethod
    def _prepare_round_keys(key: int) -> list:
        """
        Формирование 32 раундовых ключа из 256-битного ключа
        (Разбиваем 256-битный ключ на 8 32-битных частей. Затем формируем 32 раундовых ключа:
          - Первые 24 раунда 8 ключей повторяются три раза
          - Последние 8 раундов 8 ключей берутся в обратном порядке)
        :param key: исходный 256-битный ключ
        :return: список из 32 раундовых ключей
        """
        # Разбиваем ключ на 8 подключей по 32 бит
        subkeys = []
        for round in range(8):
            # Сдвигаем ключ вправо на 32 бит и отсекаем маской до 32 бит
            subkey = key >> (round * 32) & 0xFFFFFFFF
            subkeys.append(subkey)

        # Формируем 32 раундовых ключа
        round_keys = []
        for step in range(1,5):
            round_keys.extend(subkeys if step < 4 else subkeys[::-1])

        return round_keys

    @classmethod
    def _s_box_replacement(cls, data: int) -> int:
        """
        Применяем S-блоки к 32-битному блоку данных
        (Разбиваем 32-битное слово на 8 4-битных частей (нибблов); для каждого ниббла применяем соответствующую таблицу подстановок)
        :param data: 32-битный блок
        :return: преобразованный блок
        """
        replaced_data = 0
        # Обрабатываем 8 групп по 4 бита (начиная со старших)
        for part in range(8):
            # Определяем сдвиг для текущей группы (позиция бита в 32-битном числе куда встанет 4-битное значение своим младшим битом)
            shift = 28 - part * 4

            # Извлекаем 4-битный фрагмент
            # (побитовое И, Маска 0xF (15 в десятичной, 1111 в двоичной системе), т.е. обнуляет все биты, кроме последних четырех)
            # (перемещаем нужные 4 бита в младшие разряды числа, выделяем последние 4 бита (ниббл) после сдвига)
            nibble = (data >> shift) & 0xF

            # Выбираем соответствующий S-блок из таблицы замен (4-битное значение после замены через S-блок (число от 0 до 15))
            replaced = cls.S_BOX[part][nibble]

            # Добавляем результат в нужную позицию (побитовое ИЛИ)
            # (изначально result инициализируется нулём, и каждый фрагмент занимает свою уникальную позицию в 32 битах. Операция ИЛИ позволяет накапливать все фрагменты без перекрытия)
            replaced_data |= replaced << shift

        return replaced_data

    @staticmethod
    def _cyclic_shift(data: int, shift: int = 11) -> int:
        """
        Циклический сдвиг 32-битного блока влево на shift (по умолчанию 11 бит)
        :param data: исходный блок
        :param shift: кол-во бит для сдвига
        :return: сдвинутый блок
        """
        # Сдвигаем данные влево на shift бит и обрезаем до 32 бит
        shifted_left = (data << shift) & 0xFFFFFFFF

        # Сдвигаем данные вправо, чтобы получить выбывшие биты
        shifted_right = data >> (32 - shift)

        # Объединяем части
        # (если сложить их через ИЛИ, то биты из shifted_left и shifted_right объединятся, так как в shifted_left освободившиеся справа биты заполнены нулями, а в shifted_right — слева тоже нули. Таким образом, ИЛИ объединит эти части без перекрытия)
        return shifted_left | shifted_right

    @classmethod
    def _round_function(cls, left_part: int, right_part: int, round_key: int) -> int:
        """
        Раундовая функция Фейстеля
        :param left_part: левая часть 64-битного блока данных (32 бита)
        :param right_part: правая часть 64-битного блока данных (32 бита)
        :param round_key: раундовый ключ (32 бита)
        :return: результат преобразования
        """
        # Сложение с ключом по модулю 2^32
        new_right_part = (right_part + round_key) & 0xFFFFFFFF

        # Нелинейное преобразование через S-блоки
        new_right_part = cls._s_box_replacement(new_right_part)

        # Циклический сдвиг влево на 11 бит
        new_right_part = cls._cyclic_shift(new_right_part)

        # XOR с левой частью
        new_right_part = new_right_part ^ left_part

        return new_right_part

    @staticmethod
    def _split_block(block: int) -> tuple[int,int]:
        """
        Разделяет 64-битный блок данных на левую и правую части
        :param block: исходный 64-битный блок данных в виде целого числа
        :return: левая и правая части по 32 бит
        """
        left_part = (block >> 32) & 0xFFFFFFFF  # Старшие 32 бита
        right_part = block & 0xFFFFFFFF  # Младшие 32 бита
        return left_part, right_part

    def _encrypt_block(self, block: int) -> int:
        """
        Шифрует 64-битный блок данных
        :param block: исходный 64-битный блок данных в виде целого числа
        :return: зашифрованный блок
        """
        # Разделяем блок на левую и правую части
        left_part, right_part = self._split_block(block)

        # Выполняем 32 раунда преобразований
        for round in range(32):
            # Извлекаем раундовый ключ
            round_key = self.round_keys[round]

            # Вычисляем новую правую часть
            new_right_part = self._round_function(left_part, right_part, round_key)

            # Перестановка блоков кроме последнего
            if round == 31:
                left_part = new_right_part
            else:
                left_part, right_part = right_part, new_right_part

        # Объединяем части в зашифрованный блок
        return (left_part << 32) | right_part

    def _decrypt_block(self, block: int) -> int:
        """
        Расшифровывает 64-битный блок данных
        :param block: зашифрованный блок
        :return: расшифрованный блок
        """
        # Разделяем блок на левую и правую части
        left_part, right_part = self._split_block(block)

        # Выполняем раунды в обратном порядке
        for round in reversed(range(32)):
            # Извлекаем раундовый ключ
            round_key = self.round_keys[round]

            # Вычисляем новую правую часть
            new_right_part = self._round_function(left_part, right_part, round_key)

            # Перестановка блоков кроме последнего
            if round == 0:
                left_part = new_right_part
            else:
                left_part, right_part = right_part, new_right_part

        # Объединяем части в зашифрованный блок
        return (left_part << 32) | right_part

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Шифрует данные произвольной длины с использованием PKCS#7 padding.
        :param plaintext: исходные данные в виде байтов
        :return: шифртекст
        """
        # Добавление PKCS#7 padding к данным
        padded_data = pkcs7.pad(plaintext)
        # Дополняем блок нулями, если он меньше 8 байт
        if len(padded_data) < 8:
            padded_data += b'\x00' * (8 - len(padded_data))

        # Шифруем по блокам
        # (Данные разбиваются на блоки по 64 бита (8 байт))
        encrypted_data = b''
        for byte in range(0, len(padded_data), 8):
            data = padded_data[byte:byte + 8]
            block = int.from_bytes(data, byteorder='big')
            encrypted_block = self._encrypt_block(block)
            encrypted_data += encrypted_block.to_bytes(8, byteorder='big')

        return encrypted_data

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Расшифровывает данные с PKCS#7 padding
        :param ciphertext: шифртекст
        :return: исходные данные
        """
        # Расшифровываем по блокам
        # (Шифртекст разбивается на блоки по 64 бита)
        decrypted_data = b''
        for byte in range(0, len(ciphertext), 8):
            data = ciphertext[byte:byte + 8]
            block = int.from_bytes(data, byteorder='big')
            decrypted_block = self._decrypt_block(block)
            decrypted_data += decrypted_block.to_bytes(8, byteorder='big')

        # Удаление PKCS#7 padding
        return pkcs7.unpad(decrypted_data)

class MagmaCBC(Magma):
    """
    Симметричный блочный алгоритм шифрования "Магма" (ГОСТ Р 34.12-2015)
    (шифрование и расшифрование 64-битных блоков)
    РЕЖИМ: CBC (Cipher Block Chaining) - предыдущий блок используется в качестве входных данных для следующей итерации шифрования после XOR с исходным блоком открытого текста
    """

    def __init__(self, key: int, iv: bytes = None):
        """
        Инициализация шифра.
        :param key: 256-битный ключ в виде целого числа
        :param iv: вектор инициализации (64 бит)
        """
        super().__init__(key)

        self.iv = iv.ljust(8, b'\x00')[:8] if iv else os.urandom(8)
        if self.iv != iv:
            print(f"Сгенерирован вектор инициализации (hex): {self.iv.hex()}")

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Шифрует данные произвольной длины с использованием PKCS#7 padding и вектора инициализации
        1. Инициализация IV: Первый блок расшифровки комбинируется с исходным IV.
        2. Циклическая обработка:
            - Каждый зашифрованный блок расшифровывается базовым алгоритмом
            - Результат XOR-ится с предыдущим зашифрованным блоком (не расшифрованным!)
            - Текущий зашифрованный блок сохраняется как «предыдущий» для следующей итерации
        3. Удаление padding: После обработки всех блоков удаляется дополнение.
        :param plaintext: исходные данные в виде байтов
        :return: шифртекст
        """
        # Добавление PKCS#7 padding к данным
        padded_data = pkcs7.pad(plaintext)
        # Дополняем блок нулями, если он меньше 8 байт
        if len(padded_data) < 8:
            padded_data += b'\x00' * (8 - len(padded_data))

        # Инициализация предыдущего блока вектором инициализации (IV)
        previous = self.iv

        # Шифруем по блокам
        # (Данные разбиваются на блоки по 64 бита (8 байт))
        encrypted_data = b''
        # 4. Обработка данных блоками по 64 бита (8 байт)
        for byte in range(0, len(padded_data), 8):
            data = padded_data[byte:byte + 8]

            # XOR текущего блока данных с предыдущим результатом (IV → зашифрованный блок)
            xored_data = bytes(b ^ p for b, p in zip(data, previous))
            xored_block = int.from_bytes(xored_data, 'big')

            # Шифрование результата XOR
            encrypted_block = self._encrypt_block(xored_block)
            encrypted_bytes = encrypted_block.to_bytes(8, 'big')
            encrypted_data += encrypted_bytes

            # Обновление предыдущего блока для следующей итерации
            previous = encrypted_bytes

        return encrypted_data

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Расшифровывает данные с PKCS#7 padding и вектором инициализации
        :param ciphertext: шифртекст
        :return: исходные данные
        """
        # Инициализация предыдущего блока вектором инициализации (IV)
        previous = self.iv

        # Расшифровываем по блокам
        # (Шифртекст разбивается на блоки по 64 бита)
        decrypted_data = b''
        for byte in range(0, len(ciphertext), 8):
            data = ciphertext[byte:byte + 8]
            block = int.from_bytes(data, byteorder='big')

            # Расшифровка блока базовым алгоритмом
            decrypted_block = self._decrypt_block(block)
            decrypted_bytes = decrypted_block.to_bytes(8, 'big')

            # XOR результата с предыдущим блоком (IV → зашифрованный блок)
            xored_data = bytes(d ^ p for d, p in zip(decrypted_bytes, previous))
            decrypted_data += xored_data

            # Обновление предыдущего блока для следующей итерации
            previous = data

        # Удаление PKCS#7 padding
        return pkcs7.unpad(decrypted_data)


def interactive_mode():
    """Интерактивный режим работы через консоль"""
    print('*** Шифрование/расшифрование на основе шифра "Магма" (ГОСТ Р 34.12-2015) ***')
    print("-------------------------------------------------------------------------------------------------", end='\n\n')

    try:
        # режим работы шифра
        while True:
            operation = input("Выберите операцию шифрования (зашифровать - [encrypt], расшифровать - [decrypt]): ").strip().lower()
            if operation not in ["e", "encrypt", "d", "decrypt"]:
                print("Ошибка: некорректный выбор операции шифрования (необходимо выбрать из списка: 'e', 'encrypt', 'd', 'decrypt')", end='\n\n')
                continue
            break
        is_encrypt_operation = operation in ["e", "encrypt"]
        # --------------------------------------------------------------------------------------------------------------

        # определение ключа шифрования (256 бит = 64 hex-символа)
        key = 0
        while True:
            key_hex = input("Введите 256-битный ключ (64 hex-символа): ").strip()
            if len(key_hex) != 64:
                print("Ошибка: ключ должен быть 64 символа!", end='\n\n')
                continue
            try:
                key = int(key_hex, 16)
                break
            except:
                print("Ошибка: некорректный hex-формат ключа!", end='\n\n')
                continue
        # --------------------------------------------------------------------------------------------------------------

        # Выбор режима
        while True:
            mode = input("Выберите режим работы (ECB/CBC): ").strip().upper()
            if mode not in ["ECB", "CBC"]:
                print("Ошибка: недопустимый режим (необходимо выбрать из списка: [ECB], [CBC]", end='\n\n')
                continue
            break
        is_cbc_mode = (mode == "CBC")
        # --------------------------------------------------------------------------------------------------------------

        # Для CBC запрашиваем вектор инициализации
        iv = None
        if is_cbc_mode:
            if is_encrypt_operation:
                iv_choice = input("Использовать случайный вектор инициализации? (y/n): ").strip().lower()
                if iv_choice == 'y':
                    iv = os.urandom(8)
                    print(f"Сгенерирован вектор инициализации (hex): {iv.hex()}")
            if not iv:
                while True:
                    iv_hex = input("Введите вектор инициализации (16 hex-символов): ").strip()
                    if len(iv_hex) != 16:
                        print("Ошибка: вектор инициализации должен быть быть длиной 16 hex-символов (8 байт)!", end='\n\n')
                        continue
                    try:
                        iv = bytes.fromhex(iv_hex)
                        break
                    except:
                        print("Ошибка: некорректный hex-формат вектора инициализации!", end='\n\n')
                        continue
        # --------------------------------------------------------------------------------------------------------------

        # выбор источника данных
        while True:
            source = input("Выберите источник данных (текст - [text], файл - [file]): ").strip().lower()
            if source not in ["t", "text", "f", "file"]:
                print("Ошибка: некорректный выбор источника данных (необходимо выбрать из списка: [t], [text], [f], [file])", end='\n\n')
                continue
            break
        is_file_source = source in ["f", "file"]
        # --------------------------------------------------------------------------------------------------------------

        # указание конкретного источника
        while True:
            if is_file_source:
                file_path = input("Введите путь к файлу (в бинарном формате): ").strip()
                if not os.path.exists(file_path):
                    print("Ошибка: файл с данными не найден!", end='\n\n')
                    continue
                with open(file_path, "rb") as data_file:
                    data = data_file.read()
            else:
                text = input("Введите текст: ").strip()
                if not text:
                    print("Ошибка: текст для обработки не указан!", end='\n\n')
                    continue
                data = text.encode("utf-8") if is_encrypt_operation else bytes.fromhex(text)
            break
        # --------------------------------------------------------------------------------------------------------------

        # выбор режима вывода данных
        while True:
            output = input("Куда вывести результат (консоль - [console], файл - [file]): ").strip().lower()
            if output not in ["c", "console", "f", "file"]:
                print("Ошибка: некорректный выбор режима вывода данных (необходимо выбрать из списка: [c], [console], [f], [file])", end='\n\n')
            break
        is_file_output = output in ["f", "file"]
        # --------------------------------------------------------------------------------------------------------------

        # Инициализация шифра и Обработка данных
        cipher = MagmaCBC(key, iv) if is_cbc_mode else Magma(key)
        result_data = cipher.encrypt(data) if is_encrypt_operation else cipher.decrypt(data)

        # Вывод результата
        if is_file_output:
            file_path = input("Введите путь для сохранения файла (в бинарном формате): ").strip()
            with open(file_path, "wb") as output_file:
                output_file.write(result_data)
            print(f"Данные сохранены в '{file_path}'")
        else:
            print(f"\n{('Зашифрованный' if is_encrypt_operation else 'Расшифрованный')} текст:")
            try:
                print(result_data.decode("utf-8"))
            except:
                print(result_data.hex())
    except Exception as ex:
        print(f"Ошибка: {ex}", file=sys.stderr)
        sys.exit(1)

def arguments_mode():
    """Режим обработки аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description='Шифрование/расшифрование на основе шифра "Магма" (ГОСТ Р 34.12-2015)',
        formatter_class=argparse.RawTextHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help="Операция зашифрования")
    group.add_argument("-d", "--decrypt", action="store_true", help="Операция расшифрования")

    parser.add_argument("-k", "--key", type=str, required=True, default="ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", help="256-битный ключ в hex-формате (64 символа)")

    parser.add_argument("-m", "--mode", choices=["ecb", "cbc"], default="ecb", help="Режим шифрования (по умолчанию: ecb)")
    parser.add_argument("-v", "--iv", type=str, help="Вектор инициализации для CBC режима (16 hex-символов)")

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-t", "--text", type=str, help="Текст для обработки")
    input_group.add_argument("-i", "--input", type=str, help="Входной файл (в бинарном формате)")

    parser.add_argument("-o", "--output", type=str, help="Выходной файл (в бинарном формате)")

    args = parser.parse_args()

    try:
        # Обработка ключа (проверка на длину и преобразование из hex-строки в число)
        if len(args.key) != 64:
            raise ValueError("Ключ должен быть длиной 256 бит (64 hex-символа)")
        key = int(args.key, 16)

        # Для CBC проверяем вектор инициализации
        iv = None
        if args.mode == "cbc":
            if args.decrypt and not args.iv:
                raise ValueError("Для расшифрования с CBC режимом необходимо указать вектор инициализации [--iv]")
            iv = bytes.fromhex(args.iv) if args.iv else os.urandom(8)
            if args.encrypt and not args.iv:
                print(f"Сгенерирован вектор инициализации (hex): {iv.hex()}")

        # Получение входных данных
        if args.text:
            data = args.text.encode("utf-8") if args.encrypt else bytes.fromhex(args.text)
        elif args.input:
            if not os.path.exists(args.input):
                raise ValueError(f"Файл с данными не найден")
            with open(args.input, "rb") as data_file:
                data = data_file.read()
        else:
            raise ValueError("Текст для обработки или Входной файл не указаны")

        # Инициализация шифра и Обработка данных
        cipher = MagmaCBC(key, iv) if args.mode == "cbc" else Magma(key)
        result_data = cipher.encrypt(data) if args.encrypt else cipher.decrypt(data)

        # Вывод результата
        if args.output:
            with open(args.output, "wb") as output_file:
                output_file.write(result_data)
            print(f"Записано в файл [{output_file.name}] : {len(result_data)} байт")
        else:
            try:
                print(result_data.decode("utf-8"))
            except UnicodeDecodeError:
                print(result_data.hex())
    except Exception as ex:
        print(f"Ошибка: {ex}", file=sys.stderr)
        sys.exit(1)

def main():
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        arguments_mode()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрервано пользователем...")


# if __name__ == "__main__":
#     # Тестовые данные из задания
#     key = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
#     plaintext = "fedcba9876543210"
#     # Исходный текст (больше 64 бит)
#     # plaintext = "Hello world! This is a test message."
#
#     # Инициализация шифра
#     pkcs7.ALWAYS_PADDED = None
#     magma = Magma(key)
#
#     # Шифрование
#     ciphertext = magma.encrypt(plaintext.encode('utf-8'))
#     print(f"Шифртекст (hex): {ciphertext.hex()}")  # 4ee901e5c2d8ca3d
#
#     # Расшифрование
#     decrypted = magma.decrypt(ciphertext)
#     print(f"Расшифровано: {decrypted.decode('utf-8')}")  # fedcba9876543210