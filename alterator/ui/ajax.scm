(define-module (ui syscall-inspector ajax)
    :use-module (alterator ajax)
    :use-module (alterator algo)
    :use-module (alterator woo)
    :export (init))

(define (do-update)
  (catch/message
   (lambda ()
     (let ((data (woo-read-first "/syscall-inspector")))
       (let ((message (woo-get-option data 'data)))
         (form-update-value "data_display" message))))))

(define (on-load)
  (form-bind "update_button" "click" do-update)
  (do-update)
  )

(define init on-load)
