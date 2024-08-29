# ==================================================================================================================


from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import AbstractUser


# ==================================================================================================================
    

# Define o modelo CustomUser que estende o modelo AbstractUser do Django
class CustomUser(AbstractUser):
    """
    Modelo de usuário personalizado estendendo o AbstractUser do Django.

    Campos:
        email: Campo de e-mail único e indexado.
        first_name: Nome do usuário, com limite de 20 caracteres.
        email_confirmed: Flag indicando se o e-mail do usuário foi confirmado.
        groups: Relacionamento com o grupo de permissões do Django.
        user_permissions: Relacionamento com as permissões do Django.
    """

    # Campo para o e-mail do usuário, que deve ser único
    email = models.EmailField(unique=True, db_index=True)  

    # Campo para o primeiro nome do usuário
    first_name = models.CharField(max_length=20)
    
    # Campo para confirmar o cadastro via e-mail
    email_confirmed = models.BooleanField(default=False)

    # Relacionamentos com grupos e permissões do Django
    groups = models.ManyToManyField('auth.Group', related_name='customuser_groups')
    user_permissions = models.ManyToManyField('auth.Permission', related_name='customuser_permissions')

    def __str__(self):
        # Define a representação em string do objeto como o e-mail
        return self.email
    

# ==================================================================================================================

