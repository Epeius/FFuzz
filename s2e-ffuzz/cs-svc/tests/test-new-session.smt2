(get-session-id)
(set-logic QF_AUFBV )
(declare-fun arr1 () (Array (_ BitVec 32) (_ BitVec 8) ) )
(declare-fun arr2 () (Array (_ BitVec 32) (_ BitVec 8) ) )

(assert (=  
            (_ bv0 32) 
            (bvand  
                 (bvadd  
                      (_ bv4294967177 32) 
                      (
                         (_ zero_extend 24)  
                         (select  arr1 (_ bv0 32) ) 
                      ) 
                 ) 
                 (_ bv255 32)
            ) 
        ) 
)

(assert (= 
           (_ bv123 8) 
           (select arr1 (_ bv1 32))
        ) 
)

(check-sat)
;(get-value (arr1))
;(get-value (arr2))
(get-value ( (select arr1 (_ bv1 32))))
(get-value ( (select arr1 (_ bv0 32))))


