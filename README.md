# Симметричный блочный шифр "Магма" (ГОСТ Р 34.12-2015)

Проект реализует алгоритм шифрования «Магма», утверждённый стандартом ГОСТ Р 34.12-2015. 
Программа позволяет зашифровать и расшифровать данные в режимах ECB и CBC с использованием 256-битного ключа и 64-битного вектора инициализации (для CBC).

Алгоритм представляет собой точную копию алгоритма блочного шифрования из старого советского ГОСТ 28147—89, за исключением одного изменения. В новом ГОСТ 34.12—2015 определена и задана таблица перестановок для нелинейного биективного преобразования, которая в старом ГОСТ 28147—89 отсутствовала, и организация оставляла за собой право реализации или выбора s-боксов.

---

## Теоретическое описание алгоритма

Алгоритм «Магма» относится к блочным симметричным шифрам и имеет следующие особенности:

- **Длина шифруемого блока:** 64 бита.  
  Перед шифрованием 64-битный блок делится на две равные части по 32 бита – левую (A0) и правую (A1).
- **Длина ключа:** 256 бит.  
  Исходный ключ разбивается на 8 подклучей по 32 бита.
- **Раунды шифрования:** 32 итерации (раунда).  
  Для каждого раунда используется раундовый ключ, который определяется следующим образом:
  - Первые 24 раунда используют 8 подклучей, повторённых три раза.
  - Последние 8 раундов используют 8 подклучей в обратном порядке.
- **Структура раунда:**  
  Каждый раунд (за исключением тридцать второй, где обмен местами не производится) строится по принципу сети Фейстеля и включает следующие шаги:
  1. **Сложение по модулю 2³²:** Правая часть (32 бита) складывается с текущим раундовым ключом.
  2. **Нелинейное преобразование (S-box):** Полученное 32-битное число делится на 8 4-битных блоков (нибблов). Для каждого ниббла применяется соответствующая таблица подстановок, которая заменяет исходное 4-битное значение на другое.
  3. **Циклический сдвиг:** Результат нелинейного преобразования циклически сдвигается влево на 11 разрядов. При этом выбывающие биты «окружаются» и попадают в правую часть числа.
  4. **Операция XOR:** Полученное значение ксорится с левой частью блока.
  5. **Перестановка:** Результат (новое значение правой части) записывается, а текущая правая часть переходит на место левой. В последнем раунде обмен местами не выполняется – объединяются итоговая левая и правая части.
- **Режимы работы:**  
  Программа поддерживает режим ECB (Electronic Codebook), в котором каждый 64-битный блок обрабатывается независимо, и режим CBC (Cipher Block Chaining), где предыдущий зашифрованный блок используется для обработки следующего блока посредством операции XOR.
- **PKCS#7 Padding:**  
  Для работы с данными произвольной длины применяется схема дополнения PKCS#7, которая гарантирует, что длина данных будет кратна 8 байтам (64 бита).

### Процесс работы алгоритма
В алгоритме блок, подлежащий зашифрованию (64 бита), разделяется на 2 равные по длине части — левую (старшие 32 бита) и правую (младшие 32 бита). Далее выполняется 32 итерации с использованием итерационных ключей, получаемых из исходного 256-битного ключа шифрования.

Во время каждой итерации (кроме 32й) с левой и правой половиной зашифровываемого блока производится одно преобразование, основанное на сети Фейстеля. 

Сначала правая часть складывается по модулю 2³² с текущим итерационным ключом, затем полученное 32-битное число делится на восемь 4-битных чисел и каждое из них, используя таблицы перестановки, преобразуется в другое 4-битное число (нелинейное биективное преобразование). После этого преобразования полученное число циклически сдвигается влево на 11 разрядов. Далее результат XOR-ится с левой половиной блока. Получившееся 32-битное число записывается в правую половину блока, а старое содержимое правой половины переносится в левую половину блока.

В ходе последней (32й) итерации, аналогично вышеописанному процессу, преобразуется правая половина, после чего полученный результат пишется в левую часть исходного блока, а правая половина сохраняет свое значение.

Итерационные ключи получаются из исходного 256-битного ключа. Исходный ключ делится на восемь 32-битных подключей, и далее они используются в следующем порядке: 3 раза с 1-го по 8-й, и 1 раз с 8-го по 1-й.

Для расшифрования используется такая же последовательность итераций, как и при зашифровании, но порядок следования ключей изменяется на обратный.

---

## Описание режима CBC
**Cipher Block Chaining (CBC)** — это режим блочного шифрования, в котором каждый блок открытого текста перед зашифрованием XOR-ится с результатом зашифрования предыдущего блока (или с вектором инициализации [IV] для самого первого блока). 

### Основные этапы работы алгоритма в режиме CBC:
1. **Инициализация:**  
   - Для первого блока используется вектор инициализации (IV).  
   - Вектор инициализации (64 бит) может быть задан явно или сгенерирован случайным образом.
2. **XOR с предыдущим зашифрованным блоком:**  
   - Для **первого** блока открытых данных происходит XOR с IV.  
   - Для **каждого следующего** блока происходит XOR с результатом **предыдущего** зашифрованного блока.
3. **Зашифрование:**  
   - Полученный результат XOR (64 бит) зашифровывается базовым алгоритмом «Магма».  
   - Результат зашифрования сохраняется как «предыдущий зашифрованный блок» для следующей итерации.
4. **Расшифрование:**  
   - При расшифровании каждый 64-битный зашифрованный блок сначала расшифровывается.  
   - После расшифрования результат XOR-ится с предыдущим зашифрованным блоком (или с IV для первого блока).  
   - Таким образом восстанавливается исходный блок открытых данных.
5. **Обработка всех блоков:**  
   - Процесс повторяется для всех блоков, а результат каждого шага используется для следующего.
6. **Преимущество CBC:**  
   - Изменение одного бита в блоке данных приводит к изменению всех последующих блоков, что повышает криптостойкость и скрывает повторяющиеся паттерны.  
   - Для расшифрования требуется тот же вектор инициализации (IV), что и при зашифровании.

---

## Описание работы программы

Программа написана на Python и реализует алгоритм симметричного шифрования **Магма** (ГОСТ Р 34.12-2015), поддерживая два режима работы: **ECB** (Electronic Codebook) и **CBC** (Cipher Block Chaining). Программа зашифровывает и расшифровывает данные, делая это через 32 раунда шифрования с использованием 256-битного ключа. 

### Структура кода
- **Классы `Magma` и `MagmaCBC`:**  
  - Реализуют базовые операции алгоритма «Магма»: подготовку раундовых ключей, работу S-box, циклический сдвиг, разделение блока, а также функции для шифрования и дешифрования 64-битных блоков.
  - В проекте класс `MagmaCBC` наследует базовый класс `Magma` и переопределяет методы `encrypt` и `decrypt` таким образом, чтобы учитывать XOR с предыдущим блоком и использовании вектора инициализации (IV).
- **Функции `interactive_mode()` и `arguments_mode()`:**  
  - Обеспечивают два способа запуска программы.
  - В интерактивном режиме пользователь вводит данные через консоль.
  - В режиме с аргументами командной строки используются параметры, передаваемые при запуске скрипта.
- **Модуль `PKCS7Padding`:**  
  - Отвечает за дополнение (padding) данных по схеме PKCS#7. Он гарантирует, что длина данных будет кратна размеру блока (8 байт), добавляя в конец данных k байт, значение каждого из которых равно k. При расшифровке последний байт указывает, сколько байт было добавлено, и они удаляются.
- **Функция `main()`:**  
  - Определяет, какой режим запуска использовать (интерактивный, если аргументы отсутствуют, или командный с параметрами).

### Ключ шифрования
Программа использует 256-битный ключ, который принимается в hex-формате (64 символа). Например: `ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfcfdfeff`.  
Ключ преобразуется в целое число, и из него генерируются 32 раундовых ключа для шифрования с помощью метода `_prepare_round_keys`. Этот метод разбивает исходный ключ на 8 подключей по 32 бита, а затем повторяет их в прямом и обратном порядке для формирования полного набора раундовых ключей.

### Алгоритм шифрования
- **S-блоки**: Для нелинейного преобразования данных применяются 8 таблиц замен (S-блоков), соответствующих ГОСТ. Каждый 4-битный фрагмент данных заменяется значением из таблицы с помощью метода `_s_box_replacement`.
- **Раундовая функция**: На каждом из 32 раундов выполняются:  
  1. Сложение с раундовым ключом по модулю 2³²  
  2. Замена бит через S-блоки  
  3. Циклический сдвиг влево на 11 бит (`_cyclic_shift`)  
  4. XOR результата с левой половиной блока  
- **Режимы работы**:  
  - **ECB**: Каждый 64-битный блок шифруется независимо.  
  - **CBC**: Использует вектор инициализации (IV). Перед шифрованием каждый блок XOR-ится с результатом шифрования предыдущего блока. При отсутствии IV программа генерирует его автоматически через `os.urandom`.

### Работа с данными
- **Дополнение**: Для выравнивания размера данных до кратного 8 байтам применяется схема PKCS#7 через модуль `PKCS7Padding`.
- **Обработка блоков**: Данные разбиваются на 64-битные блоки. Методы `_encrypt_block` и `_decrypt_block` выполняют базовые операции шифрования/расшифрования, а методы `encrypt` и `decrypt` управляют потоком данных, добавляя/удаляя дополнение.
- **Поддержка форматов**:  
  - Текст: автоматическое кодирование в UTF-8 при шифровании  
  - Файлы: обработка в бинарном режиме  
  - Вывод: отображение в hex при наличии непечатаемых символов  

### Интерфейсы

#### Интерактивный режим через консоль
При запуске без аргументов программа предлагает:  
1. Выбрать операцию (шифрование/расшифрование)  
2. Указать 256-битный ключ в hex-формате  
3. Выбрать режим (ECB/CBC)  
4. Для CBC: ввести или сгенерировать 64-битный IV  
5. Указать источник данных (текст/файл)  
6. Настроить вывод результата (консоль/файл)  

#### Командный режим в терминале с параметрами
Программа поддерживает параметры:  
-  `-h, --help` Отображение справочной информации по применяемым параметрам
-  `-e, --encrypt` Операция зашифрования данных
-  `-d, --decrypt` Операция расшифрования данны
-  `-k, --key <ключ>` Ключ шифрования в hex-формате (256 бит или 64 символа)
-  `-m, --mode <режим>` Режим шифрования (по умолчанию: ecb)
-  `-v, --iv <IV>` Вектор инициализации в hex-формате (64 бит или 16 символов)
-  `-t, --text <текст>` Текст для обработки
-  `-i, --input <файл>` Входной файл (в бинарном формате)
-  `-o, --output <файл>` Выходной файл (в бинарном формате)

### Особенности безопасности
- **Генерация вектора инициализации**: Для CBC режима используется криптостойкий генератор `os.urandom`, если вектор не указан вручную.
- **Валидация**: Проверка длины ключа (64 hex-символа) и IV (16 hex-символов) на этапе ввода.
- **Обработка ошибок**: Программа перехватывает исключения при неверном формате данных, поврежденном дополнении или проблемах с файлами.

### Примечания:
- **PKCS#7 padding** гарантирует, что длина данных будет кратна размеру блока (64 бита).
- Режим **CBC** более безопасен, так как каждый блок зависит от предыдущего.
- Для режима **CBC** вектор инициализации (IV) должен быть одинаковым при шифровании и расшифровке.
- В программе используется обработка ошибок, например, для неверного формата ключа или данных.
- Программа поддерживает шифрование и расшифровку как текстовых строк, так и файлов с выводом в консоль или в файл.

---

## Модуль PKCS#7 Padding

Модуль `PKCS7Padding` реализует механизм дополнения (padding) данных для блочных шифров, чтобы длина исходного сообщения была кратна размеру блока. Ниже приведён подробный разбор функционала модуля:

### Класс `PKCS7Padding`

```python
class PKCS7Padding:
    """
    PKCS#7 padding - механизм, позволяющий привести длину данных к нужному кратному размеру блока, который требуется для блочных шифров.
    - Дополняет данные до кратного размера блока, добавляя k байт со значением k.
    - При расшифровке последний байт сообщает, сколько байт padding было добавлено, и они удаляются.
    - Это позволяет гарантировать, что после шифрования и расшифрования исходные данные сохраняются корректно.
    """
    ALWAYS_PADDED: bool = True
```

- **ALWAYS_PADDED:**  
  Флаг, указывающий, всегда ли следует добавлять padding даже в случае, когда данные уже кратны размеру блока.

### Метод `pad`

```python
    def pad(cls, data: bytes, block_size: int = 8, always_padded: bool = None) -> bytes:
        """
        Дополняет данные по схеме PKCS#7 до кратного размера block_size.
        :param data: исходные данные
        :param block_size: размер блока (по умолчанию 8 байт)
        :param always_padded: если True, padding добавляется всегда, даже если данные уже кратны размеру блока.
        :return: данные с padding
        """
```

- **Пояснение:**
  - Вычисляется остаток от деления длины данных на размер блока.
  - Если данных достаточно и они уже кратны блоку, а параметр `always_padded` выключен, возвращаются исходные данные.
  - В противном случае вычисляется количество байт, необходимых для дополнения (`pad_len`), и создаётся последовательность байтов, каждый из которых равен `pad_len`.
  - Дополнение (padding) добавляется в конец данных.

### Метод `unpad`

```python
    def unpad(cls, data: bytes, always_padded: bool = None) -> bytes:
        """
        Удаляет padding, добавленный PKCS#7.
        :param data: данные с padding
        :param always_padded: флаг, указывающий, что padding всегда присутствует
        :return: данные без padding
        """
```

- **Пояснение:**
  - Метод получает последний байт данных, который указывает, сколько байт padding было добавлено.
  - Проверяются корректность значения padding и соответствие всех последних байт значению `pad_len`.
  - Если padding корректен, он удаляется, и возвращаются исходные данные без дополнения.

---

## Варианты запуска программы

Программа поддерживает два основных режима запуска:

### 1. Интерактивный режим в консоли

Запуск без параметров:
```shell
python magma.py
```
В этом режиме программа:
- Запросит выбор операции (зашифрование/расшифрование).
- Попросит ввести ключ шифрования в hex-формате (256 бит или 64 символа).
- Предложит выбрать режим шифрования (ECB или CBC).  
  (При выборе CBC можно ввести вектор инициализации в hex-формате (64 бит или 16 символов) или выбрать автоматическую генерацию случайного вектора инициализации)
- Запросит источник данных: текст для обработки или путь к файлу (в бинарном формате).
- Предложит выбор вывода результата: консоль или файл.
- После обработки результат будет выведен согласно выбору пользователя.

### 2. Командный режим в терминале с параметрами

Запуск программы с использованием аргументов командной строки:
```
python magma.py [-h] (-e | -d) -k <ключ> [-m <режим>] [-v <IV>] (-t <текст> | -i <входной_файл>) [-o <выходной_файл>]
```

**Описание параметров:**
- `-h` или `--help`  
  Отображение справочной информации по применяемым параметрам.
- `-e` или `--encrypt`  
  Операция зашифрования данных.
- `-d` или `--decrypt`  
  Операция расшифрования данных.
- `-k <ключ>`, `--key <ключ>`  
  Ключ шифрования в hex-формате (256 бит или 64 символа). Обязательный параметр.
  ```
  -k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  ```
- `-m <режим>`, `--mode <режим>`  
  Режим шифрования: `ecb` или `cbc`. По умолчанию используется `ecb`.
  ```
  -m cbc
  ```
- `-v <IV>`, `--iv <IV>`  
  Вектор инициализации для режима CBC в hex-формате (64 бит или 16 символов).
  ```
  -v 0123456789abcdef
  ```
- `-t <текст>`, `--text <текст>`  
  Текст для обработки. Если производится зашифрование, текст берётся как строка, если расшифрование — ожидается hex-строка.
  ```
  -t "Шифрование/расшифрование на основе шифра Магма (ГОСТ Р 34.12-2015)"
  ```
- `-i <файл>`, `--input <файл>`  
  Путь к входному файлу (в бинарном формате). Альтернативный способ указания источника данных.
- `-o <файл>`, `--output <файл>`  
  Путь для сохранения результата в файл (в бинарном формате). Если не указан, результат выводится в консоль.

---

## Примеры вариантов запуска

### Режим 1. Интерактивный в консоли

#### Пример 1.1. Зашифрование в режиме ECB с консольным вводом и выводом
```
*** Шифрование/расшифрование на основе шифра "Магма" (ГОСТ Р 34.12-2015) ***
-------------------------------------------------------------------------------------------------

Выберите операцию шифрования (зашифровать - [encrypt], расшифровать - [decrypt]): encrypt
Введите ключ шифрования в hex-формате (64 символа): ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Выберите режим работы (ECB/CBC): ECB
Выберите источник данных (текст - [text], файл - [file]): text
Введите текст: Шифрование/расшифрование на основе шифра Магма (ГОСТ Р 34.12-2015)
Куда вывести результат (консоль - [console], файл - [file]): console

Зашифрованный текст:
90cc275a2ccb05aa7107cbc8296f886d9c505275984af877ea89ec2e5e2518e2d271eece242b9548cec7caf10f58aaa2e43482a07ca17e5ec5ce124426f01848da6ed52dcb7502d6f646184142d1846304c13a43141db541a4fee6855b18d3b44329c8de219d40158aa5cf797a55f6c371924cef493a5137
```

#### Пример 1.2. Зашифрование в режиме CBC с вводом с консоли и выводом в файл
```
*** Шифрование/расшифрование на основе шифра "Магма" (ГОСТ Р 34.12-2015) ***
-------------------------------------------------------------------------------------------------

Выберите операцию шифрования (зашифровать - [encrypt], расшифровать - [decrypt]): encrypt
Введите ключ шифрования в hex-формате (64 символа): ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Выберите режим работы (ECB/CBC): CBC
Использовать случайный вектор инициализации? (y/n): y
Сгенерирован вектор инициализации (hex): 1b039f4414c040fb
Выберите источник данных (текст - [text], файл - [file]): text
Введите текст: Шифрование/расшифрование на основе шифра Магма (ГОСТ Р 34.12-2015)
Куда вывести результат (консоль - [console], файл - [file]): file
Введите путь для сохранения файла (в бинарном формате): encrypted_data.bin

Записано в файл [encrypted_data.bin] : 120 байт
```

#### Пример 1.3. Расшифрование в режиме CBC с вводом из файла и выводом в консоль
```
*** Шифрование/расшифрование на основе шифра "Магма" (ГОСТ Р 34.12-2015) ***
-------------------------------------------------------------------------------------------------

Выберите операцию шифрования (зашифровать - [encrypt], расшифровать - [decrypt]): decrypt
Введите ключ шифрования в hex-формате (64 символа): ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
Выберите режим работы (ECB/CBC): CBC
Введите вектор инициализации в hex-формате (16 символов): 1b039f4414c040fb
Выберите источник данных (текст - [text], файл - [file]): file
Введите путь к файлу (в бинарном формате): encrypted_data.bin
Куда вывести результат (консоль - [console], файл - [file]): console

Расшифрованный текст:
Шифрование/расшифрование на основе шифра Магма (ГОСТ Р 34.12-2015)
```

### Режим 2. Командный через терминал с параметрами

#### Пример 2.1. Шифрование текста в режиме ECB, вывод в консоль

```shell
python magma.py -e -k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff -m ecb -t "Шифрование/расшифрование на основе шифра Магма (ГОСТ Р 34.12-2015)"
```

**Описание параметров:**
- `-e`: Операция шифрования.
- `-k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff`: Ключ шифрования в hex-формате (256 бит или 64 символа).
- `-m ecb`: Режим шифрования ECB.
- `-t "Шифрование/расшифрование на основе шифра Магма (ГОСТ Р 34.12-2015)"`: Текст для шифрования.

**Примечание:** Результат шифрования будет выведен в консоль. Текст шифруется без использования файла и в режиме ECB.

---

#### Пример 2.2. Шифрование текста в режиме CBC с вектором инициализации, вывод в файл

```shell
python magma.py -e -k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff -m cbc -v 0123456789abcdef -t "Шифрование/расшифрование на основе шифра Магма (ГОСТ Р 34.12-2015)" -o encrypted_output.bin
```

**Описание параметров:**
- `-e`: Операция шифрования.
- `-k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff`: Ключ шифрования в hex-формате (256 бит или 64 символа).
- `-m cbc`: Режим шифрования CBC.
- `-v 0123456789abcdef`: Вектор инициализации в hex-формате (64 бит или 16 символов).
- `-t "Шифрование/расшифрование на основе шифра Магма (ГОСТ Р 34.12-2015)"`: Текст для шифрования.
- `-o encrypted_output.bin`: Путь для сохранения зашифрованных данных.

**Примечание:** Результат шифрования будет сохранён в файл `encrypted_output.bin`. Вектор инициализации используется в режиме CBC.

---

#### Пример 2.3. Шифрование данных из файла в режиме ECB, вывод в файл

```shell
python magma.py -e -k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff -m ecb -i input.txt -o encrypted_output.bin
```

**Описание параметров:**
- `-e`: Операция шифрования.
- `-k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff`: Ключ шифрования в hex-формате (256 бит или 64 символа).
- `-m ecb`: Режим шифрования ECB.
- `-i input.txt`: Путь к файлу с исходными данными для шифрования.
- `-o encrypted_output.bin`: Путь для сохранения зашифрованных данных.

**Примечание:** Результат шифрования исходных данных из файла `input.txt` будет сохранён в файл `encrypted_output.bin` в режиме ECB.

---

#### Пример 2.4. Расшифрование из файла в режиме ECB, вывод в файл

```shell
python magma.py -d -k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff -m ecb -i encrypted_output.bin -o decrypted_output.txt
```

**Описание параметров:**
- `-d`: Операция расшифрования.
- `-k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff`: Ключ шифрования в hex-формате (256 бит или 64 символа).
- `-m ecb`: Режим шифрования ECB.
- `-i encrypted_output.bin`: Путь к файлу с зашифрованными данными.
- `-o decrypted_output.txt`: Путь для сохранения расшифрованных данных.

**Примечание:** Результат расшифрованного текста из файла `encrypted_output.bin` будет записан в файл `decrypted_output.txt`.

---

#### Пример 2.5. Расшифрование из файла в режиме CBC с вектором инициализации, вывод в консоль

```shell
python magma.py -d -k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff -m cbc -v 0123456789abcdef -i encrypted_output.bin
```

**Описание параметров:**
- `-d`: Операция расшифрования.
- `-k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff`: Ключ шифрования в hex-формате (256 бит или 64 символа).
- `-m cbc`: Режим шифрования CBC.
- `-v 0123456789abcdef`: Вектор инициализации в hex-формате (64 бит или 16 символов).
- `-i encrypted_output.bin`: Путь к файлу с зашифрованными данными.

**Примечание:** Результат расшифрованного текста будет выведен в консоль.

---

#### Пример 2.6. Расшифрование данных из файла в режиме CBC с вектором инициализации, вывод в файл

```shell
python magma.py -d -k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff -m cbc -v 0123456789abcdef -i encrypted_output.bin -o decrypted_output.txt
```

**Описание параметров:**
- `-d`: Операция расшифрования.
- `-k ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff`: Ключ шифрования в hex-формате (256 бит или 64 символа).
- `-m cbc`: Режим шифрования CBC.
- `-v 0123456789abcdef`: Вектор инициализации в hex-формате (64 бит или 16 символов).
- `-i encrypted_output.bin`: Путь к файлу с зашифрованными данными.
- `-o decrypted_output.txt`: Путь для сохранения расшифрованных данных.

**Примечание:** Результат расшифрованного текста будет записан в файл `decrypted_output.txt`.

---

### Дополнение к командам:
- Для всех команд, параметр `-k` (ключ) и `-m` (режим) обязательны.
- Параметры `-v` (вектор инициализации), `-i` (входной файл) и `-o` (выходной файл) могут быть использованы в зависимости от типа работы (режим CBC, чтение и запись из/в файл).
- Если выбрана операция зашифрования в режиме CBC, и не указан параметр `-v` (вектор инициализации), то он будет сгенерирован автоматически и выведен в консоль.

---

## Тестовые данные

Для проверки работы программы можно использовать следующие тестовые данные:

- **Ключ (256 бит, hex):**  
  `ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff`

- **Вектор инициализации (64 бит, hex):**  
  `0123456789abcdef`

- **Открытый текст:**  
  `Шифрование/расшифрование на основе шифра Магма (ГОСТ Р 34.12-2015)`

- **Зашифрованный текст (ECB режим):**  
  `90cc275a2ccb05aa7107cbc8296f886d9c505275984af877ea89ec2e5e2518e2d271eece242b9548cec7caf10f58aaa2e43482a07ca17e5ec5ce124426f01848da6ed52dcb7502d6f646184142d1846304c13a43141db541a4fee6855b18d3b44329c8de219d40158aa5cf797a55f6c371924cef493a5137`

- **Зашифрованный текст (CBC режим):**  
  `be9bdbd1238d458e610248cff00cf98a14527af5c227c4b27ea951fc1d968db58c66bd1660abc0e81844d213291feeb1bda21346f657a6ee988bdf9a59cd0b9422d2680d65d2022d19aaf304f90e28b3506eae7b8f38e23cd0ff9696c53d00d49708fc4467f5d1f3956843405e2fd710d8a2064d8b4b3f93`

---