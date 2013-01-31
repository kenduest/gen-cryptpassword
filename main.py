# *-* coding: utf-8 *-*

"""

version: 0.3
author: kenduest - kenduest@gmail.com

"""

import crypt,random

####################################################################

class kenduest_crypt:

    pw_chars_array = list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
    
    salt_chars_array = list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789,/')
    
    crypt_id = { 'DES'     : { "salt_prefix" : ""    , "salt_length" : 2  }  ,  
                 'MD5'     : { "salt_prefix" : "$1$" , "salt_length" : 16 }  , 
                 'SHA-256' : { "salt_prefix" : "$5$" , "salt_length" : 16 }  , 
                 'SHA-512' : { "salt_prefix" : "$6$" , "salt_length" : 16 }     
                  }

####################################################################
             
    def genrandompassword(self,length=100):    

        pw_result = []
        pw_result = [ random.choice(self.pw_chars_array) for i in range(0,length) ]        
        return "".join(pw_result)

####################################################################
        
    def hashpw(self, password, crypt_type) :
                
        return crypt.crypt(password, self.gensalt(crypt_type))

####################################################################
    
    def get_crypt_method(self):
        #return self.crypt_method
        return [ x for x in sorted(self.crypt_id) ]

####################################################################    
    def gensalt(self, ctype_type) :
        
        supported_crypt_method = self.get_crypt_method()
        
        self.xtype = str(ctype_type).upper()
            
        if self.xtype not in supported_crypt_method :
            raise NotImplementedError
                                
        salt_result = [ random.choice(self.salt_chars_array) for i in range(0,self.crypt_id[self.xtype]["salt_length"]) ]
        result = self.crypt_id[self.xtype]["salt_prefix"] + "".join(salt_result)
            
        return result
    
####################################################################

def test1() :

    if len(sys.argv) != 3 :
        return False
    
    pw = kenduest_crypt();
    password = sys.argv[1]
    t = sys.argv[2]
        
    try :
        print(pw.hashpw(password, t))
        
    except(NotImplementedError) :
        print("Sorry, unspoorted type: %s" % t)

    return True
        

####################################################################

def test2() :
    
    pw = kenduest_crypt();
    
    if len(sys.argv) == 1 :
        password = pw.genrandompassword(10)
    else :   
        password = sys.argv[1]

    print("Password is %s" % password)
        
    try :
        for t in pw.get_crypt_method() :
            print("using %s, result: %s" % (t, pw.hashpw(password, t)))
                
    except(NotImplementedError) :
        print("Sorry, unspoorted type: %s" % t) 


####################################################################

if __name__ == "__main__" :
    import sys     

if not test1() :
    test2()    
