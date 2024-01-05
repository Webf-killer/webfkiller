import os


def format_json(file_content):
    # JSON 객체를 분리하기 위해 '}\n{' 문자열을 '},\n{'로 대체
    formatted_content = file_content.replace("}\n{", "},\n{")
    # 모든 객체를 포함하는 배열로 만들기 위해 대괄호 추가
    formatted_content = "[" + formatted_content + "]"
    return formatted_content


current_folder_path = os.getcwd()


def format_all_json_in_current_folder(folder_path):
    for file_name in os.listdir(folder_path):
        if file_name.endswith(".json"):
            file_path = os.path.join(folder_path, file_name)

            with open(file_path, "r") as file:
                file_content = file.read()

            # 파일이 '['로 시작하지 않으면 포맷팅을 수행합니다.
            if not file_content.startswith("["):
                formatted_content = format_json(file_content)

                with open(file_path, "w") as file:
                    file.write(formatted_content)


format_all_json_in_current_folder(current_folder_path)
