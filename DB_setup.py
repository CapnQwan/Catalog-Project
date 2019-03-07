import random, string
from sqlalchemy.ext.declarative import declarative_base
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)


Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(64))
    email = Column(String(32))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
    	s = Serializer(secret_key, expires_in = expiration)
    	return s.dumps({'id': self.id })

    @staticmethod
    def verify_auth_token(token):
    	s = Serializer(secret_key)
    	try:
    		data = s.loads(token)
    	except SignatureExpired:
    		return None
    	except BadSignature:
    		return None
    	user_id = data['id']
    	return user_id


class CatalogItem(Base):
    __tablename__ = 'catalog_item'

    id = Column(Integer, primary_key = True)
    name = Column(String(40), nullable = False)
    catagory = Column(String(30), nullable = False)
    description = Column(String(250))
    price = Column(String(12), nullable = False)
    View = Column(Integer, nullable = False)
    filename = Column(String, nullable = False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       return {
           'Id'   :self.id,
           'Name'   : self.name,
           'Catagory'   : self.catagory,
           'Description'   : self.description,
           'Price'   : self.price,
           'user_id'   : self.user_id,
       }

engine = create_engine('sqlite:///Catalog.db')


Base.metadata.create_all(engine)