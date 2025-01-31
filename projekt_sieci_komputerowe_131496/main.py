import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
import whois
from datetime import datetime
import os


class DomainChecker:
    def __init__(self):
        self.window = tk.Tk()
        self.input_button = None
        self.input_file = None
        self.generate_button = None
        self.text_area = None
        self.status_label = None
        self.setup_gui()

        self.queue = queue.Queue()

        self.report_data = []

        self.check_queue()

    def check_queue(self):
        while not self.queue.empty():
            task = self.queue.get()
            task()
        self.window.after(50, self.check_queue)

    def setup_gui(self):
        self.window.title("Informacje o domenach")
        self.window.geometry("800x600")
        self.window.configure(bg='#f0f0f0')

        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(
            header_frame,
            text="Sprawdzanie informacji o domenach",
            font=('Helvetica', 16, 'bold')
        ).pack()

        input_frame = ttk.LabelFrame(main_frame, text="Wybór pliku", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 20))

        self.input_button = ttk.Button(
            input_frame,
            text="Wybierz plik z domenami",
            command=self.handle_input_button
        )
        self.input_button.pack(pady=5)

        self.status_label = ttk.Label(
            input_frame,
            text="Nie wybrano pliku",
            foreground='gray'
        )
        self.status_label.pack()

        results_frame = ttk.LabelFrame(main_frame, text="Wyniki", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))

        self.text_area = scrolledtext.ScrolledText(
            results_frame,
            width=70,
            height=15,
            font=('Courier', 10)
        )
        self.text_area.pack(fill=tk.BOTH, expand=True)

        actions_frame = ttk.Frame(main_frame)
        actions_frame.pack(fill=tk.X)

        self.generate_button = ttk.Button(
            actions_frame,
            text="Zapisz raport",
            command=self.save_report,
            state='disabled'
        )
        self.generate_button.pack(pady=5)

    def handle_input_button(self):
        self.text_area.delete(1.0, tk.END)

        def select_input_file():
            self.input_file = filedialog.askopenfilename(
                title="Wybierz plik z listą domen",
                filetypes=[("Pliki tekstowe", "*.txt"), ("Wszystkie pliki", "*.*")]
            )
            if self.input_file:
                self.status_label.config(
                    text=f"Wybrany plik: {os.path.basename(self.input_file)}",
                    foreground='green'
                )
                self.input_button.configure(state='disabled')
                self.start_fetching_thread()

        select_input_file()

    def start_fetching_thread(self):
        thread = threading.Thread(target=self.generate_report)
        thread.daemon = True
        thread.start()

    @staticmethod
    def calculate_days_remaining(expiration_date):
        if expiration_date:
            today = datetime.now()
            days_remaining = (expiration_date - today).days
            return max(0, days_remaining)
        return None

    def check_domain(self, domain):
        try:
            w = whois.whois(domain)
            print(w)
            expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date

            return {
                'registrar': w.registrar or "Brak danych",
                "org": w.org or "Brak danych",
                'whois_server': w.whois_server or "Brak danych",
                'creation_date': (w.creation_date[0] if isinstance(w.creation_date, list)
                                  else w.creation_date or "Brak danych"),
                'expiration_date': expiration_date or "Brak danych",
                'days_remaining': self.calculate_days_remaining(expiration_date) if expiration_date else "Brak danych"
            }
        except Exception as e:
            return {
                'registrar': "Błąd",
                'creation_date': "Błąd",
                'expiration_date': "Błąd",
                'days_remaining': "Błąd"
            }

    def generate_report(self):
        try:
            with open(self.input_file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]

            self.queue.put(lambda: self.text_area.insert(tk.END, "RAPORT INFORMACJI O DOMENACH\n", "=" * 50 + "\n\n"))

            for domain in domains:
                info = self.check_domain(domain)
                domain_entry = (
                        f"Domena: {domain}\n"
                        f"Serwer odpowiedzi: {info['whois_server']} \n"
                        f"Rejestrator: {info['registrar']}\n"
                        f"Właściciel: {info['org']} \n"
                        f"Data rejestracji: {info['creation_date']}\n"
                        f"Data wygaśnięcia: {info['expiration_date']}\n"
                        f"Pozostało dni: {info['days_remaining']}\n"
                        + "-" * 50 + "\n\n"
                )
                self.report_data.append(domain_entry)
                self.queue.put(lambda: self.text_area.insert(tk.END, domain_entry))

                time.sleep(0.1)
        except Exception as e:
            self.queue.put(lambda: self.status_label.config(text=f"Błąd: {str(e)}", foreground='red'))
        else:
            self.queue.put(lambda: self.generate_button.configure(state='normal'))
        finally:
            self.queue.put(lambda: self.input_button.configure(state='normal'))

    def save_report(self):
        try:
            if not self.report_data:
                raise ValueError("Brak danych do zapisania")

            output_file = filedialog.asksaveasfilename(
                title="Zapisz raport",
                defaultextension=".txt",
                filetypes=[("Pliki tekstowe", "*.txt")],
                initialfile="raport.txt"
            )

            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.writelines(self.report_data)

                self.queue.put(lambda: self.status_label.config(
                    text=f"Raport zapisany: {os.path.basename(output_file)}",
                    foreground='green'
                ))

        except Exception as e:
            self.queue.put(lambda: self.status_label.config(
                text=f"Błąd zapisu: {str(e)}",
                foreground='red'
            ))

    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    app = DomainChecker()
    app.run()
