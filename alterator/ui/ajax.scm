(define-module (ui syscall-inspector ajax)
    :use-module (alterator ajax)
    :use-module (alterator algo)
    :use-module (alterator woo)
    :use-module (ice-9 threads)
    :export (init))
(define *auto-update-thread* #f)

(define (do-update)
  (catch/message
   (lambda ()
     (let ((data (woo-read-first "/syscall-inspector" '(("method" . "read")))))
       (let ((message (woo-get-option data 'data)))
         (form-update-value "data_display" message))))))

(define (auto-update-loop)
  (while #t
    (sleep 5)
    (do-update))) 
(define (load-filter)
  (catch/message
   (lambda ()
     (let ((data (woo-read-first "/syscall-inspector" '(("method" . "read_filter")))))
       (let ((filter-val (woo-get-option data 'filter)))
         (form-update-value "filter_input" filter-val))))))

(define (save-filter)
  (catch/message
   (lambda ()
     (let ((new-filter (form-get-value "filter_input")))
       (form-update-value "filter_status" "Применение...")
       (let ((data (woo-read-first "/syscall-inspector"
                                 `(("method" . "write_filter")
                                   ("filter_value" . ,new-filter)))))
         (form-update-value "filter_status" "Фильтр применен!")
         (form-update-value "filter_input" (woo-get-option data 'new_filter))
         (do-update)))))) 
(define (on-load)
  (form-bind "save_filter_button" "click" save-filter)
  (load-filter)
  (do-update)
  
  (if (not *auto-update-thread*)
      (set! *auto-update_thread* (spawn-thread auto-update-loop)))
  )

(define init on-load)
