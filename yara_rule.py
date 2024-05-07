import random
import string
import yara
import os
import re
import logging

class YaraRuleTester:
    def __init__(self, root_directory):
        self.logger = logging.getLogger(__name__)  # Inicialize o logger primeiro
        self.root_directory = root_directory
        self.compiled_rules = self.compile_rules()

    def compile_rules(self):
        compiled_rules = []
        for root, dirs, files in os.walk(self.root_directory):
            for file in files:
                if file.endswith(('.yara', '.yar')):
                    full_path = os.path.join(root, file)
                    try:
                        rule = yara.compile(filepath=full_path)
                        compiled_rules.append((rule, full_path))
                        self.logger.info(f"Successfully compiled rule: {full_path}")
                    except yara.SyntaxError as e:
                        self.logger.error(f"Error compiling rule {full_path}: {e}")
        return compiled_rules

    def extract_rule_details(self):
        rule_details = []
        for rule, path in self.compiled_rules:
            with open(path, 'r', encoding='utf-8') as file:
                rule_text = file.read()
                rule_details.extend(self.parse_rule_text(rule_text, path))
        return rule_details

    def parse_rule_text(self, rule_text, path):
        rule_name_matches = re.findall(r'rule\s+(\w+)', rule_text)
        string_rules_matches = re.findall(r'(\$\w+)\s*=\s*(\"[^\"]+\"|\{[^\}]+\})', rule_text)
        return [
            {
                "rule_name": rule_name,
                "rule_file": path,
                "string_rules": [{"identifier": match[0], "content": match[1].strip('"')} for match in
                                 string_rules_matches]
            }
            for rule_name in rule_name_matches
        ]

    def test_rules(self):
        rule_details = self.extract_rule_details()
        test_results = []
        total_tests = 0
        total_matches = 0

        for detail in rule_details:
            rule, _ = next((item for item in self.compiled_rules if item[1] == detail['rule_file']), (None, None))
            for string_rule in detail['string_rules']:
                total_tests += 1
                content = self.generate_random_paragraph(string_rule['content'])
                matches = rule.match(data=content.encode('utf-8')) if rule else []
                matched = bool(matches)
                total_matches += matched
                test_results.append(self.format_result(detail, content, matched))

        return test_results, total_tests, total_matches

    def generate_random_paragraph(self, yara_content):
        # Gera palavras aleatórias adicionais
        additional_words = [''.join(random.choices(string.ascii_letters, k=random.randint(3, 10))) for _ in range(100)]

        # Adiciona a string yara_content à lista de palavras aleatórias
        mixed_words = [yara_content] + additional_words
        random.shuffle(mixed_words)

        # Gera frases aleatórias com as palavras misturadas
        paragraph = ' '.join(mixed_words)

        return paragraph

    def format_result(self, detail, content, matched):
        return {
            "rule_name": detail['rule_name'],
            "rule_file": detail['rule_file'],
            "string_tested": content,
            "matched": matched
        }

    def display_results(self, show_only_false_matches=False):
        results, total_tests, total_matches = self.test_rules()
        for result in results:
            if not show_only_false_matches or (show_only_false_matches and not result['matched']):
                self.logger.info(
                    f"Rule: {result['rule_name']}, File: {result['rule_file']}, Tested String: {result['string_tested']}, Match: {result['matched']}"
                )

        match_percentage = (total_matches / total_tests) * 100 if total_tests > 0 else 0
        self.logger.info(
            f"\nTotal Tests: {total_tests}, Total Matches: {total_matches}, Match Percentage: {match_percentage:.2f}%"
        )


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    yara_tester = YaraRuleTester('rules')  # Test rules in the current directory
    yara_tester.display_results(show_only_false_matches=False)
