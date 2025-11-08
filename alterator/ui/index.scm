(document:surround "/std/frame")

(vbox
 (margin "10")
 (label text (bold "Инспектор Syscall (ACC)"))
 (label text " ")
 
 (textbox name "data_display" height 400)

 (label text " ")
 (button name "update_button" text "Обновить данные из БД")
 )

(document:root
  (when loaded (if (defined? 'on-load) (on-load))))
