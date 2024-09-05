
#
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

---

## 🗺 Tabela de conteúdos

<ul>
  <li><a href="#-diagrama">📈 Diagrama</a></li>
  <li><a href="#-pitch-deck---entenda-nosso-projeto">🏆 Pitch Deck - Entenda nosso Projeto</a></li>
  <li><a href="#-Detalhes-do-Projeto">✒️ Detalhes do Projeto</a></li>
  <li><a href="#-features">⛳ Features</a></li>
  <li><a href="#-mais-informações">👀 Mais informações</a></li>
</ul>

---

## 📈 Diagrama 
![3 840](https://github.com/user-attachments/assets/677f2c9f-06f2-4878-b5ab-e54f25b732f1)

---

## ✒️ Detalhes do Projeto

<details>
  <summary><h3>🔍 Resumo da Proposta</h3></summary>
  <p align="left">
    <h4>
      O projeto visa desenvolver uma plataforma web para análise de programas maliciosos em arquivos APK (Android Application Package). Diversos estudos mostram um crescente número de vítimas alvo desses programas maliciosos, que teve um grande aumento após o período da pandemia do coronavírus (2020), com milhares de vítimas diárias dessas aplicações, reforçando a necessidade crítica dessa iniciativa. A proposta do projeto visa integrar diversas plataformas de análise já existentes com outras tecnologias embutidas, como, por exemplo, a API VirusTotal, implementação das Yara Rules, novas funcionalidades e tecnologias no processo de análise.
      <br><br>
      A nossa plataforma se destaca pela centralização e agilidade no acesso às informações sobre programas maliciosos, assim como a utilização de processos para análise dinâmica e estática dos arquivos em questão. Ao contrário dos métodos atuais, que são lentos, manuais e pouco intuitivos, onde a grande maioria possui apenas análises do tipo estáticas, oferecemos uma solução robusta e eficiente. Profissionais técnicos poderão obter rapidamente informações centralizadas, sem a necessidade de utilizar múltiplas ferramentas. Além disso, a plataforma é aberta para contribuições (open source), permitindo que especialistas contribuam com novas técnicas e ferramentas de análise.
      <br><br>
      Após a análi![3 840](https://github.com/user-attachments/assets/4ece046c-a527-4112-9978-584cb63a5ec7)
se, os APKs processados serão armazenados em um banco de dados dedicado, transformando-se em uma valiosa fonte de consulta e tornando-se mais um diferencial da plataforma. Essa base de dados estará acessível através da plataforma web, proporcionando um recurso contínuo e expansível para futuras consultas e análises de segurança mais detalhadas.
      <br><br>
      A entrega final do MVP (Minimum Viable Product) visa fornecer uma plataforma estável, intuitiva e altamente disponível, com diversas ferramentas e serviços integrados. O MVP também será escalável, permitindo a adição de novas funcionalidades e a avaliação contínua de programas maliciosos.
      <br><br>
      O projeto está profundamente conectado com disciplinas de Redes de Computadores, especialmente Programação para Redes, aplicando conceitos de programação para sockets, uso de APIs (Application Programming Interface), acesso a bancos de dados e criação de um webservice próprio. A plataforma será estruturada e configurada em um ambiente Linux (Orange Pi 1.0.2 Bookworm, Debian based), utilizando os servidores web Nginx e Gunicorn, a linguagem Python, o framework Django, banco de dados PostgreSQL, e Dockers para análises mais avançadas. Além disso, serão implementadas outras tecnologias para garantir alta performance e segurança, assegurando um ambiente robusto e confiável para os usuários.
    </h4>
  </p>
</details>
<details>
  <summary><h3>🔐 Introdução</h3></summary>
  <p align="left">
    <h4>
      A segurança de rede, em síntese, refere-se tanto à proteção contra o uso malicioso de informações, quanto à preservação da autenticidade e da confiabilidade de dados. Além disso, visa mitigar ameaças para manter a disponibilidade e a integridade. No entanto, evidencia-se o surgimento de Malwares, softwares feitos com a intenção de ameaçar um sistema e/ou seus usuários. Segundo Gandotra, Bansal e Sofat (2014), o Malware representa uma das ameaças mais difíceis enfrentadas pela Tecnologia da Informação atualmente, e aproximadamente 47% das organizações sofreram incidentes de segurança nos últimos anos.
      <br><br>
      Nesse contexto, este projeto visa facilitar o acesso das pessoas a informações sobre malwares, integrando ferramentas e técnicas que auxiliarão na análise e triagem de softwares que comprometem a estabilidade de serviços e a confidencialidade de usuários. Dessa forma, busca-se alcançar um ambiente mais confiável e seguro para os utilizadores de plataformas com sistema operacional Android.
      <br><br>
      De acordo com a pesquisa realizada por Djeena, Bouridane, Rubab e Marou (2023), evidencia-se uma era de guerra cibernética, na qual a espionagem virtual é uma prática altamente ativa nas plataformas Android. Além disso, constata-se que cerca de 50% dos novos malwares são variantes de outros já existentes. Portanto, torna-se imprescindível adotar estratégias de proteção contra essas ameaças para mitigá-las. A partir dessas considerações, busca-se demonstrar o desenvolvimento de meios para tal objetivo.
    </h4>
  </p>
</details>
<details>
  <summary><h3>📄 Justificativa</h3></summary>
  <p align="left">
    <h4>
      Nos últimos anos, as ameaças à cibersegurança têm crescido exponencialmente, destacando a relevância deste projeto para enfrentar a proliferação de malware na era digital. Além disso, ao enfatizar a importância da educação e conscientização sobre segurança virtual, auxilia na proteção e preservação da integridade do ciberespaço.
      <br><br>
      A produção deste projeto tem como os principais diferenciais:
      <ol>
        <li>Automatização de Processos Manuais na Análise: A automação é essencial para aumentar a eficiência na proteção contra programas mal-intencionados, proporcionando mais autonomia e agilidade no processo de análise.</li>
        <li>Integração de Serviços: A centralização de diversos serviços e APIs facilita o acesso a várias técnicas e ferramentas já existentes na comunidade de cibersegurança.</li>
        <li>Melhoria e Atualizações Contínuas: Implementação de um ciclo de feedback contínuo para aprimorar constantemente as técnicas de detecção e resposta a incidentes, com atualizações e inclusão de novas ferramentas.</li>
        <li>Análises Estáticas e Dinâmicas: Oferece a capacidade de realizar tanto análises estáticas quanto dinâmicas. Enquanto muitas plataformas se limitam às análises estáticas, a nossa utiliza Docker para executar análises dinâmicas, proporcionando uma visão mais aprofundada sobre o comportamento dos arquivos.</li>
        <li>Plataforma Web Intuitiva: Desenvolvemos uma interface web intuitiva que facilita a interação e operação da plataforma, melhorando a experiência do usuário.</li>
        <li>Histórico e Registro de Análises: Um diferencial significativo é a capacidade de cadastrar uma conta de usuário, permitindo o acompanhamento de todas as análises realizadas, com detalhamentos e relatórios completos. Isso proporciona um controle detalhado sobre as análises e facilita a gestão de dados e resultados.</li>
      </ol>
      <br>
      O desenvolvimento deste projeto integra os conteúdos das seguintes disciplinas do Projeto Pedagógico do Curso (PPC) de Tecnologia em Redes de Computadores:
      <ol>
        <li>Programação para Redes
          <ul>
            <li>Acesso a Banco de Dados:
              <ul>
                <li>Conexão e Consulta ao Banco de Dados: Estabelecimento de conexões e execução de consultas para recuperação de dados.</li>
              </ul>
            </li>
            <li>WebServices:
              <ul>
                <li>Desenvolvimento de Objetos e Classes: Criação de componentes reutilizáveis para facilitar a integração de serviços e clareza do código fonte.</li>
                <li>Integração com o Banco de Dados: Utilização de dados armazenados em bancos de dados (Logins e Dados de Análises) em nossa plataforma web.</li>
              </ul>
            </li>
            <li>Geração de Scripts:
              <ul>
                <li>Geração de Scripts para Automatização da Análise: Desenvolvimento de scripts para automatizar as análises estáticas realizada no arquivo.</li>
              </ul>
            </li>
          </ul>
        </li>
        <li>Administração de Sistemas Abertos
          <ul>
            <li>Administração de Serviços de Rede:
              <ul>
                <li>Preparação e administração dos serviços de redes para suportar a demanda, conexões e garantir a sua estabilidade/disponibilidade.</li>
              </ul>
            </li>
            <li>Servidor Web (HTTP): Utilizado na criação de um servidor web por meio do Nginx para hospedar o projeto e fornecer acesso aos usuários.</li>
            <li>Servidor de Acesso Remoto Seguro (SSH): Preparado o ambiente de acesso remoto ao servidor, onde os serviços estão sendo executados, com todas as etapas de segurança necessária, para garantir a sua integridade.</li>
          </ul>
        </li>
      </ol>
      <br>
      Este projeto integrador visa permitir que demonstremos nossos conhecimentos em práticas seguras no campo de Redes de Computadores, contribuindo para o impacto positivo na segurança cibernética e social.
    </h4>
  </p>
</details>
<details>
  <summary><h3>🎯 Objetivo Geral e Objetivos Específicos</h3></summary>
  <p align="left">
    <h4>
      Este projeto tem como objetivos gerais:
      <ol>
        <li>Criação e implementação dos serviços de redes e infraestrutura interna
          <ul>
            <li>Configurar o ambiente Linux com a devida segurança (SSH, Usuários, Permissões)</li>
            <li>Configuração dos servidores web (Nginx e Gunicorn com WSGI)</li>
            <li>Configurar os Serviços de DNS e domínios</li>
            <li>Ajustar os serviços de Banco de dados e ajuste das credenciais</li>
          </ul>
        </li>
        <li>Criação e integração do Front-end da plataforma web:
          <ul>
            <li>Implementar a interface gráfica da plataforma (HTML, CSS, Bootstrap)</li>
            <li>Desenvolver a integração com a parte do Back-End e realizar testes.</li>
            <li>Adaptação e melhorias constantes na interface conforme feedback.</li>
          </ul>
        </li>
        <li>Criação e integração do Back-office com Django
          <ul>
            <li>Desenvolver funções para a administração centralizada de Serviços e Ferramentas</li>
            <li>Implementar a integração e comunicação com Banco de dados</li>
            <li>Realizar testes de carga e usabilidade das funções implementadas</li>
          </ul>
        </li>
        <li>Criação de funções para análises estáticas
          <ul>
            <li>Implementar a criação de regras Yara e seus testes em arquivos APK</li>
            <li>Implementação de Scripts em Python para detecção de padrões em arquivos APK</li>
            <li>Automatização das ferramentas e funções, bem como os testes de carga e execução.</li>
          </ul>
        </li>
        <li>Criação de ambiente para Análises Dinâmicas
          <ul>
            <li>Configurar ambiente de máquinas virtuais e Dockers para realizar análises de execução de APKs</li>
            <li>Automatização dos processos de execução de scripts de análise em APKs</li>
            <li>Retornar os dados de forma centralizada para a plataforma web, integrando todos os processos.</li>
          </ul>
        </li>
        <li>Realizar a integração de Front, Back e APIs
          <ul>
            <li>Integração da parte do Front-end com o Back-office da Plataforma</li>
            <li>Implementar comunicação eficiente com APIs externas (como o VirusTotal)</li>
            <li>Garantir a comunicação eficiente entre todas as partes da aplicação.</li>
          </ul>
        </li>
      </ol>
    </h4>
  </p>
</details>
<details>
  <summary><h3>📅 Planejamento de Sprints</h3></summary>
  <h5>
    <blockquote>
      <details>
        <summary><h4>SPRINT 1 - DATA (01/08/2024)</h4></summary>
        <p align="left">
          <strong>1.1 - Configurar o ambiente Linux com a devida segurança</strong><br>
          <strong>2.1 - Configurar o framework Django para o desenvolvimento</strong><br>
          <strong>2.2 - Integrar e conectar o Django aos serviços de redes necessários</strong><br>
        </p>
      </details>
      <details>
        <summary><h4>SPRINT 2 - DATA (08/08/2024)</h4></summary>
        <p align="left">
          <strong>1.2 - Configuração dos servidores web</strong><br>
          <strong>1.3 - Configurar os Serviços de DNS e domínios</strong><br>
          <strong>1.4 - Criação do Banco de dados e Configuração Básica</strong><br>
        </p>
      </details>
      <details>
        <summary><h4>SPRINT 3 - DATA (15/08/2024)</h4></summary>
        <p align="left">
          <strong>2.3 - Realizar a pré-integração/validação do backend com o frontend para envio de dados</strong><br>
          <strong>1.4 - Ajustar os serviços de Banco de dados e ajuste das credenciais</strong><br>
        </p>
      </details>
      <details>
        <summary><h4>SPRINT 4 - DATA (22/08/2024)</h4></summary>
        <p align="left">
          <strong>3.1 - Desenvolver a Estrutura de todo HTML, Layouts e estilos Bootstrap</strong><br>
          <strong>4.1 - Configurar ambientes Docker para execução de análises dinâmicas</strong><br>
        </p>
      </details>
      <details>
        <summary><h4>SPRINT 5 - DATA (29/08/2024)</h4></summary>
        <p align="left">
          <strong>Implementar métodos para a análise estática de arquivos APK</strong><br>
          <strong>Validação de Login com Email e Banco de Dados devlopment Extra feature</strong><br>
          <strong>Agregar API do VirusTotal ao projeto</strong><br>
        </p>
      </details>
      <details>
        <summary><h4>SPRINT 6 - DATA (05/09/2024)</h4></summary>
        <p align="left">
          <strong>Agregar Análise Dinâmica</strong><br>
          <strong>6.1 - Testar e validar a integração entre as diferentes camadas da aplicação</strong><br>
          <strong>6.2 - Realização de uma massa de testes com Malwares reais e analisar os resultados fornecidos pela plataforma</strong><br>
          <strong>6.3 - Finalizar a documentação da plataforma</strong><br>
        </p>
      </details>
    </blockquote>
    <p align="center">
      <strong>Finalizando o SPRINT 6 - DIA 05/09/2024 - COM MVP PRONTO</strong>
    </p>
  </h5>
</details>
<details>
  <summary><h3>📚 Documentação</h3></summary>
  <p align="left">
    <h4>
      Documentação de todas as ferramentas e tecnologias utilizadas no projeto:
      <br><br>
    </h4>
  </p>
</details>

<details>
  <summary><h3>📚 Referências Bibliográficas</h3></summary>
  <p align="left">
    <h4>
      As referências bibliográficas a seguir são os estudos e trabalhos acadêmicos que embasaram a proposta deste projeto, fornecendo a fundamentação teórica necessária para a sua concepção e desenvolvimento:
      <br><br>
      <ol>
        <li>Djeena, B., Bouridane, A., Rubab, S., & Marou, F. (2023). Threats and Countermeasures in Mobile Ad Hoc Networks: A Review. Journal of Network and Computer Applications.</li>
        <li>Gandotra, E., Bansal, D., & Sofat, S. (2014). Malware analysis and classification: A survey. Journal of Information Security.</li>
      </ol>
    </h4>
  </p>
</details>

---

## 🏆 Pitch Deck - Entenda nosso Projeto

https://github.com/user-attachments/assets/d3bd572d-44c9-493b-8505-7263ddb8faae

---

## ⛳ Features
- [x] Configurar o ambiente linux
- [x] Configurar o ambiente do Django para desenvolvimento
- [x] Iniciar as possibilidades de emular android (testing)
- [x] Configuração dos Servidores Web
- [x] Configuração do DNS e Domínio
- [x] Criação do Banco de dados e Configuração Básica
- [x] Validação do Backend para enviar os dados
- [x] Protótipo da Análise Dinâmica
- [x] Desenvolver a estrutura do Frontend
- [x] Integrar novas ferramentas para análise
- [x] Implementação de métodos para Análises Estáticas
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
