import csv
import os

def validate_csv_header(header):
    """ Проверяет, соответствует ли заголовок CSV ожидаемому формату. """
    expected_header = ["Source IP", "Dest IP", "Source Port", "Dest Port", "Packet Count", "Byte Count"]
    return header == expected_header

def process_traffic(input_file, output_file):
    traffic_data = {}

    # Проверяем существование файла
    if not os.path.exists(input_file):
        print(f"[Ошибка] Файл '{input_file}' не найден.")
        return

    try:
        with open(input_file, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            header = next(reader, None)  # Считываем заголовок

            # Проверяем, есть ли заголовок
            if header is None:
                print(f"[Ошибка] Файл '{input_file}' пуст или содержит некорректные данные.")
                return

            # Проверяем заголовок на соответствие ожидаемому формату
            if not validate_csv_header(header):
                print(f"[Ошибка] Неверный формат заголовка в файле '{input_file}'. Ожидалось: {validate_csv_header.__defaults__[0]}")
                return

            for row in reader:
                if not row or None in row or len(row) != 6:
                    print(f"[Ошибка] Пропущена пустая строка или некорректные данные: {row}")
                    continue  # Пропускаем ошибочную строку

                try:
                    src_ip, dst_ip, src_port, dst_port, packets, bytes_count = row
                    packets, bytes_count = int(packets), int(bytes_count)
                except ValueError:
                    print(f"[Ошибка] Некорректные данные в строке: {row}")
                    continue

                # Обновляем статистику для источника (отправленные данные)
                if src_ip not in traffic_data:
                    traffic_data[src_ip] = [0, 0, 0, 0]  # [принятые пакеты, принятые байты, отправленные пакеты, отправленные байты]
                traffic_data[src_ip][2] += packets
                traffic_data[src_ip][3] += bytes_count

                # Обновляем статистику для получателя (принятые данные)
                if dst_ip not in traffic_data:
                    traffic_data[dst_ip] = [0, 0, 0, 0]
                traffic_data[dst_ip][0] += packets
                traffic_data[dst_ip][1] += bytes_count

    except Exception as e:
        print(f"[Ошибка] Ошибка при обработке файла: {e}")
        return

    # Записываем агрегированные данные в новый CSV
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["IP адрес", "Принятые пакеты", "Принятые байты", "Переданные пакеты", "Переданные байты"])

            for ip, stats in traffic_data.items():
                writer.writerow([ip] + stats)

        print(f"[Успех] Обработанные данные сохранены в '{output_file}'")
    
    except Exception as e:
        print(f"[Ошибка] Ошибка при записи файла: {e}")

if __name__ == "__main__":
    input_filename = input("Введите имя входного CSV файла (traffic_report.csv): ").strip()
    output_filename = input("Введите имя выходного CSV файла (aggregated_traffic.csv): ").strip()

    if not input_filename:
        input_filename = "traffic_report.csv"
    if not output_filename:
        output_filename = "aggregated_traffic.csv"

    process_traffic(input_filename, output_filename)
