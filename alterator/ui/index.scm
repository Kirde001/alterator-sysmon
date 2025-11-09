(document:surround "/std/frame")

(vbox
 (margin "10")
 (label text (bold "Инспектор Syscall (ACC)"))
 (label text " ")
 
 (hbox
  (label text "Отслеживать процесс (comm): ")
  (textbox name "filter_input" text "*") 
  (button name "save_filter_button" text "Применить")
 )
 (label name "filter_status" text " ")
 
 (label text " ")
 (textbox name "data_display" height 400)

 (label text " ")
 )

(document:root
  (when loaded (if (defined? 'on-load) (on-load))))
