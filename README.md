
<h1 align="center">📌  KYRIOS - Plataforma de Análise Automatizada de Malwares em APK's Android </h1>

<p align="center">
  <img src="http://img.shields.io/static/v1?label=License&message=MIT%20License&color=A20606&style=for-the-badge"/>
  <img src="http://img.shields.io/static/v1?label=Python&message=3.11.0&color=A20606&style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/static/v1?label=Django&message=GUI/FRAMEWORK&color=A20606&style=for-the-badge&logo=Django"/>
  <img src="http://img.shields.io/static/v1?label=STATUS&message=Em%20desenvolvimento&color=A20606&style=for-the-badge"/>
</p>
<p align="center">
  <img src="http://img.shields.io/static/v1?label=Desenvolvido%20por&message=Kalvin%20Klein%20e%20Jose%20Bezerra&color=A20606&style=for-the-badge"/>
  <img src="http://img.shields.io/static/v1?label=Orientado%20por&message=Galileu%20Batista&color=A20606&style=for-the-badge"/>
  <img src="http://img.shields.io/static/v1?label=Disciplina&message=Projeto%20Integrador&color=A20606&style=for-the-badge"/>
</p>

<p align="center">

RESUMO DO PROJETO:

  O projeto visa desenvolver uma plataforma web para análise de programas maliciosos em arquivos APK (Android Application Package).
  A proposta do projeto visa integrar diversas plataformas de análise já existentes com outras tecnologias embutidas, como, por exemplo, a API VirusTotal, implementação das Yara Rules, novas funcionalidades e tecnologias no processo de análise.<br><br>
  A nossa plataforma se destaca pela centralização e agilidade no acesso às informações sobre programas maliciosos, assim como a utilização de processos para análise dinâmica e estática dos arquivos em questão. Ao contrário dos métodos atuais, que são lentos, manuais e pouco intuitivos, onde a grande maioria possui apenas análises do tipo estáticas, oferecemos uma solução robusta e eficiente. Profissionais técnicos poderão obter rapidamente informações centralizadas, sem a necessidade de utilizar múltiplas ferramentas. Além disso, a plataforma é aberta para contribuições (open source), permitindo que especialistas contribuam com novas técnicas e ferramentas de análise.<br><br>
  Após a análise, os APKs processados serão armazenados em um banco de dados dedicado, transformando-se em uma valiosa fonte de consulta e tornando-se mais um diferencial da plataforma. Essa base de dados estará acessível através da plataforma web, proporcionando um recurso contínuo e expansível para futuras consultas e análises de segurança mais detalhadas.<br><br>
  A entrega final do MVP (Minimum Viable Product) visa fornecer uma plataforma estável, intuitiva e altamente disponível, com diversas ferramentas e serviços integrados. O MVP também será escalável, permitindo a adição de novas funcionalidades e a avaliação contínua de programas maliciosos.

INTRODUÇÃO:

A segurança de rede, em síntese, refere-se tanto à proteção contra o uso malicioso de
informações, quanto à preservação da autenticidade e da confiabilidade de dados. Além
disso, visa mitigar ameaças para manter a disponibilidade e a integridade. No entanto,
evidencia-se o surgimento de Malwares, softwares feitos com a intenção de ameaçar um
sistema e/ou seus usuários. Segundo Gandotra, Bansal e Sofat (2014), o Malware
representa uma das ameaças mais difíceis enfrentadas pela Tecnologia da Informação
atualmente, e aproximadamente 47% das organizações sofreram incidentes de segurança
nos últimos anos.
Nesse contexto, este projeto visa facilitar o acesso das pessoas a informações sobre
malwares, integrando ferramentas e técnicas que auxiliarão na análise e triagem de
softwares que comprometem a estabilidade de serviços e a confidencialidade de usuários.
Dessa forma, busca-se alcançar um ambiente mais confiável e seguro para os utilizadores
de plataformas com sistema operacional Android.
De acordo com a pesquisa realizada por Djeena, Bouridane, Rubab e Marou (2023),
evidencia-se uma era de guerra cibernética, na qual a espionagem virtual é uma prática
altamente ativa nas plataformas Android. Além disso, constata-se que cerca de 50% dos
novos malwares são variantes de outros já existentes. Portanto, torna-se imprescindível
adotar estratégias de proteção contra essas ameaças para mitigá-las. A partir dessas
considerações, busca-se demonstrar o desenvolvimento de meios para tal objetivo.

JUSTIFICATIVA:

Nos últimos anos, as ameaças à cibersegurança têm crescido exponencialmente,
destacando a relevância deste projeto para enfrentar a proliferação de malware na era
digital. Além disso, ao enfatizar a importância da educação e conscientização sobre
segurança virtual, auxilia na proteção e preservação da integridade do ciberespaço.
A produção deste projeto tem como os principais diferenciais:
1 - Automatização de Processos Manuais na Análise: A automação é essencial para
aumentar a eficiência na proteção contra programas mal-intencionados,
proporcionando mais autonomia e agilidade no processo de análise.
2 - Integração de Serviços: A centralização de diversos serviços e APIs facilita o
acesso a várias técnicas e ferramentas já existentes na comunidade de
cibersegurança.
3 - Melhoria e Atualizações Contínuas: Implementação de um ciclo de feedback
contínuo para aprimorar constantemente as técnicas de detecção e resposta a
incidentes, com atualizações e inclusão de novas ferramentas.
4 - Análises Estáticas e Dinâmicas: Oferece a capacidade de realizar tanto análises
estáticas quanto dinâmicas. Enquanto muitas plataformas se limitam às análises
estáticas, a nossa utiliza Docker para executar análises dinâmicas, proporcionando
uma visão mais aprofundada sobre o comportamento dos arquivos.
5 - Plataforma Web Intuitiva: Desenvolvemos uma interface web intuitiva que facilita
a interação e operação da plataforma, melhorando a experiência do usuário.
6 - Histórico e Registro de Análises: Um diferencial significativo é a capacidade de
cadastrar uma conta de usuário, permitindo o acompanhamento de todas as
análises realizadas, com detalhamentos e relatórios completos. Isso proporciona um
controle detalhado sobre as análises e facilita a gestão de dados e resultados.
O desenvolvimento deste projeto integra os conteúdos das seguintes disciplinas do Projeto
Pedagógico do Curso (PPC) de Tecnologia em Redes de Computadores:
1. Programação para Redes
1.1. Acesso a Banco de Dados:
Conexão e Consulta ao Banco de Dados: Estabelecimento de
conexões e
execução de consultas para recuperação de dados.
1.2. WebServices:
Desenvolvimento de Objetos e Classes: Criação de componentes
reutilizáveis para facilitar a integração de serviços e clareza do código
fonte.
Integração com o Banco de Dados: Utilização de dados armazenados
em
bancos de dados (Logins e Dados de Análises) em nossa plataforma
web.
1.3. Geração de Scripts:
Geração de Scripts para Automatização da Análise: Desenvolvimento
de
scripts para automatizar as análises estáticas realizada no arquivo em
questão.
2. Administração de Sistemas Abertos
2.1. Administração de Serviços de Rede:
Preparação e administração dos serviços de redes para suportar a
demanda, conexões e garantir a sua estabilidade/disponibilidade.
2.2. Servidor Web (HTTP): Utilizado na criação de um servidor web por meio
do Nginx para hospedar o projeto e fornecer acesso aos usuários.
2.3. Servidor de Acesso Remoto Seguro (SSH): Preparado o ambiente de
acesso remoto ao servidor, onde os serviços estão sendo executados,
com todas as etapas de segurança necessária, para garantir a sua integridade.

Este projeto integrador visa permitir que demonstremos nossos conhecimentos em práticas
seguras no campo de Redes de Computadores, contribuindo para o impacto positivo na
segurança cibernética e social.

</p>

---

## 🗺 Tabela de conteúdos

<ul>
  <li><a href="#-exemplo-na-prática">Exemplo na prática</a></li>
  <li><a href="#-features">Features</a></li>
  <li><a href="#-licença">Licença</a></li>
  <li><a href="#-mais-informações">Mais informações</a></li>
</ul>

---

## 🔨 
EM DESENVOLVIMENTO....

---

## 🚀 Executando na sua máquina
EM DESENVOLVIMENTO....

### Instruções de uso
EM DESENVOLVIMENTO....

---

## ⛳ Features
- [x] Configurar o ambiente linux
- [x] Configurar o ambiente do Django para desenvolvimento
- [x] Iniciar as possibilidades de emular android (testing)
- [ ] Configuração dos Servidores Web
- [ ] Configuração do DNS e Domínio
- [ ] Criação do Banco de dados e Configuração Básica
- [ ] Validação do Backend para enviar os dados
- [ ] Protótipo da Análise Dinâmica
- [ ] Desenvolver a estrutura do Frontend
- [ ] Integrar novas ferramentas para análise
- [ ] Implementação de métodos para Análises Estáticas
- [ ] Implementação das Regras YARA
- [ ] Testar e Validar a plataforma
- [ ] Realizar a documentação da Plataforma

---

## 📝 Licença

Esse projeto está licenciado sob a licença do MIT LICENSE - veja o arquivo de [LICENÇA](LICENSE) para mais detalhes.

---

## 👀 Mais informações

Para mais informações sobre o projeto presente neste repositório ou para sugerir alterações e correções, entre em contato pelo Github ou Email.<br>

Co-Fundador: [kalvin.klein@escolar.ifrn.edu.br](mailto:kalvin.klein@escolar.ifrn.edu.br).<br>
Co-Fundador: [jose.bezerra1@escolar.ifrn.edu.br](mailto:jose.bezerra1@escolar.ifrn.edu.br).<br>
Orientador: [galileu.batista@escolar.ifrn.edu.br](mailto:galileu.batista@escolar.ifrn.edu.br).<br>

<div>
   <a href="https://github.com/kakanetwork"><img src="https://img.shields.io/badge/-GitHub Kalvin-4d080e?style=for-the-badge&color=A20606&logo=github&logoColor=ffffff"></a>
   <a href="https://github.com/JoJoseB"><img src="https://img.shields.io/badge/-GitHub José-4d080e?style=for-the-badge&color=A20606&logo=github&logoColor=ffffff"></a>
</div> 

---

<code>Feito por: kakanetwork e JoJoseB</code><br>
<code>Orientado por: Galileu Batista</code>
