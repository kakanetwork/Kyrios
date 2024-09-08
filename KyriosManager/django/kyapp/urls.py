# ==================================================================================================================


from . import views
from django.urls import path


# ==================================================================================================================


urlpatterns = [
    path('', views.signin, name="signin"),
    path('signup', views.signup, name="signup"),
    path('logout', views.deslogar, name="logout"),
    
    # ====================================================
    
    path('home', views.home, name="home"),
    path('table', views.table, name="table"),

    # ====================================================

    path('delete/<str:id>/<str:flag>/', views.deletar_analise, name='delete'),
    path('detalhar/<str:id>/', views.detalhar_analise, name='detalhar'),

    # ====================================================

    path('ativacao/', views.ativar_email, name='ativacao'),
    path('reenviar/', views.reenvio_confirmacao, name='reenvio'),

    # ====================================================

    path('download/<path:caminho_arquivo>/', views.baixar_pcap, name='baixar_pcap'),

    # ====================================================

    path('403/', views.erro_403, name='403'),
]


# ==================================================================================================================
