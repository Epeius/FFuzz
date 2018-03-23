(set-session-id 0)

;We should get the values of session 0
(get-value ( (select arr1 (_ bv1 32))))
(get-value ( (select arr1 (_ bv0 32))))


