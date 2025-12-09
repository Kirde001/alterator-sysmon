(document:surround "/std/frame")

(define (do-update)
  (catch/message
   (lambda ()
     (form-update-enum "data_table" (woo-list "/syscall-inspector")))))

(define (init-config)
  (catch/message
   (lambda ()
     (form-update-enum "log_format" (woo-list "/syscall-inspector" 'action "list_formats"))
     
     (let ((data (woo-read-first "/syscall-inspector" 'action "read_config")))
       (form-update-value-list '("siem_enabled" "log_format") data)))))

(define (save-config)
  (catch/message
   (lambda ()
     (let ((chk (form-value "siem_enabled"))
           (fmt (form-value "log_format")))
       (woo-write "/syscall-inspector" 'action "save_config" 'siem_enabled chk 'log_format fmt)))))

(vbox
  (label text (bold "Системный мониторинг (eBPF)"))
  (label text " ")

  (hbox
    align "left"
    
    (checkbox name "siem_enabled" text "Включить Syslog/SIEM" (when toggled (save-config)))
    
    (label text "      ")
    
    (label text "Формат логов: ")
    (combobox name "log_format" (when selected (save-config)))
    
    (label text "      ")
    
    (button name "update_button" text "Обновить настройки и таблицу" (when clicked (do-update)))
  )

  (label text " ")

  (listbox 
    name "data_table"
    columns 5
    header (vector "Время" "Важность" "Тип события" "Процесс" "Детали")
    row '#((time . "") (severity . "") (type . "") (process . "") (details . ""))
    enumref "/syscall-inspector"
  )
)

(document:root
  (when loaded 
    (init-config)
    (do-update)))
