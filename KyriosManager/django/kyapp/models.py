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


class AnaliseAPK(models.Model):
    """
    Modelo para armazenar informações sobre análises de arquivos APK.

    Campos:
        usuario: Relacionamento com o modelo CustomUser.
        id_json: ID JSON único para o registro da análise.
        nome: Nome do arquivo APK.
        ext: Extensão do arquivo APK.
        data: Data da análise.
        status: Status da análise (padrão: 'Analisado').
        tempo: Tempo gasto no download e envio do arquivo.
        virustotal: Dados relacionados ao resultado da análise no VirusTotal.
        estatica: Dados relacionados à análise estática do APK.
        dinamica: Outros dados gerais da análise dinamica.
    """

    # Relacionamento com o modelo CustomUser
    usuario = models.ForeignKey(CustomUser, on_delete=models.CASCADE)  
    # Campo para o ID JSON único
    id_json = models.CharField(max_length=20, unique=True)  
    # Campo para o nome do arquivo
    nome = models.CharField(max_length=255)  
    # Campo para a extensão do arquivo
    ext = models.CharField(max_length=10)  
    # Campo para a data da análise
    data = models.DateField(default=timezone.now)   
    # Campo para o status da análise
    status = models.CharField(max_length=20, default='Analisado')  
    # Campo para o tempo de download e envio
    tempo = models.TextField()  

    # Campo para itens detectados
    virustotal = models.JSONField(default=dict)
    estatica = models.JSONField(default=dict)
    dinamica = models.JSONField(default=dict)
    
    def save(self, *args, **kwargs):
        """
        Sobrescreve o método save para gerar automaticamente o ID JSON.
        """
        # Verifica se o ID JSON já está definido
        if not self.id_json:

            # Obtém o último objeto no banco de dados
            ultimo_objeto = AnaliseAPK.objects.order_by('-id').first()
            if ultimo_objeto:

                # Extrai o número do último ID JSON e gera um novo ID incrementado
                ultimo_id = ultimo_objeto.id_json.split('-')[-1]
                novo_id = int(ultimo_id) + 1
                self.id_json = f'APK-{novo_id:04d}'  # Formato APK-XXXX

            else:
                self.id_json = 'APK-0001'  # Se for o primeiro objeto

        super().save(*args, **kwargs)  # Chama o método save da superclasse


# ==================================================================================================================