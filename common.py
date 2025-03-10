class PKCS7Padding:
    """
    PKCS#7 padding - механизм, позволяющий привести длину данных к нужному кратному размеру блока, который требуется для блочных шифров
    - Дополняет данные до кратного размера блока, добавляя k байт со значением k.
    - При расшифровке последний байт сообщает, сколько байт padding было добавлено, и они удаляются.
    - Это позволяет гарантировать, что после шифрования и расшифрования исходные данные сохраняются корректно.
    """
    ALWAYS_PADDED: bool = True

    @classmethod
    def pad(cls, data: bytes, block_size: int = 8, always_padded: bool = None) -> bytes:
        """
        Дополняет данные по схеме PKCS#7 до кратного размера block_size
        :param data: исходные данные
        :param block_size: размер блока (по умолчанию 8 байт)
        :param always_padded: всегда добавлять padding в конце, даже если данные уже кратны размеру блока
        :return: данные с padding
        """
        if always_padded is None:
            always_padded = cls.ALWAYS_PADDED

        remainder = len(data) % block_size
        # Если данные уже кратны размеру блока, возвращаем их без изменений
        if (always_padded is False and remainder == 0) or always_padded is None:
            return data

        pad_len = block_size - remainder
        padding = bytes([pad_len] * pad_len)
        return data + padding

    @classmethod
    def unpad(cls, data: bytes, always_padded: bool = None) -> bytes:
        """
        Удаляет padding, добавленный PKCS#7
        :param data: данные с padding
        :param always_padded: всегда добавлять padding в конце, даже если данные уже кратны размеру блока
        :return: данные без padding
        """
        if always_padded is None:
            always_padded = cls.ALWAYS_PADDED
        if not data or always_padded is None:
            return data

        pad_len = data[-1]

        # Проверяем, что padding корректен
        if pad_len < 1 or pad_len > len(data):
            if always_padded:
                raise ValueError("Некорректный padding: некорректная длина")
            else:
                return data

        # Проверяем, что все байты padding равны pad_len
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            if always_padded:
                raise ValueError("Неверный padding: не все байты padding равны pad_len")
            else:
                return data

        return data[:-pad_len]