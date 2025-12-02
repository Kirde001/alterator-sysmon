(document:surround "/std/frame")

(define (do-update)
  (catch/message
   (lambda ()
     (form-update-enum "data_table" (woo-list "/syscall-inspector")))))

(define (update-status-label)
  (catch/message
   (lambda ()
     (let ((data (woo-read-first "/syscall-inspector" 'action "read_filter")))
       (form-update-value "current_filter_lbl" 
                          (string-append "Активный фильтр: " (woo-get-option data 'filter_list)))))))

(define (add-filter)
  (catch/message
   (lambda ()
     (let ((proc (form-value "filter_input")))
       (if (not (string-null? proc))
           (begin
             (woo-write "/syscall-inspector" 'action "add_filter" 'filter_value proc)
             (form-update-value "filter_input" "") 
             (update-status-label)
             (do-update)))))))

(define (reset-filter)
  (catch/message
   (lambda ()
     (woo-write "/syscall-inspector" 'action "reset_filter")
     (update-status-label)
     (do-update))))

(vbox
  (margin "10")
  (label text (bold "Инспектор Syscall (eBPF) + SIEM"))
  (label text " ")
 
  (hbox
   align "center"
   (label text "Добавить процесс:")
   (edit name "filter_input" width "150") 
   (button name "add_btn" text "Добавить (+)" (when clicked (add-filter)))
   (button name "reset_btn" text "Сбросить фильтр" (when clicked (reset-filter)))
  )
  
  (label name "current_filter_lbl" text "Загрузка..." align "left")

  (label text " ")

  (listbox 
    name "data_table"
    columns 5
    header (vector "Время" "PID" "Процесс" "Системный вызов" "Кол-во")
    row '#((time . "") (pid . "") (comm . "") (nr . "") (count . ""))
    enumref "/syscall-inspector"
    height 400
  )

  (label text " ")
  
  (hbox 
    align "right"
    (button name "update_button" text "Обновить таблицу" (when clicked (do-update)))
  )
)

(document:root
  (when loaded 
    (update-status-label)
    (do-update)))
