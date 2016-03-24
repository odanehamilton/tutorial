from . import db  
class Myprofile(db.Model):     
    id_num = db.Column(db.Integer, primary_key=True, unique = True)     
    first_name = db.Column(db.String(80))     
    last_name = db.Column(db.String(80)) 
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80))
 

    
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        try:
            return unicode(self.id)  # python 2 support
        except NameError:
            return str(self.id)  # python 3 support

    def __repr__(self):
        return '<User %r>' % (self.username)