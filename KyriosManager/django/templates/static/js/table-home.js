function fecharModal(button) {
    // Encontre o modal pai do botão clicado
    var modal = button.closest('.modal');
    if (modal) {
        // Remova a classe 'show' do modal
        modal.classList.remove('show');
        // Remova o atributo 'aria-modal' para esconder o modal do leitor de tela
        modal.setAttribute('aria-modal', 'false');
        // Remova a classe 'modal-open' do body para corrigir a rolagem da página
        document.body.classList.remove('modal-open');

        // Remova apenas a classe 'show' do backdrop
        var backdrop = document.querySelector('.modal-backdrop');
        if (backdrop) {
            backdrop.classList.remove('show');
        }
    }
}


$(document).ready(function(){
    $('.excluir-btn').click(function(e){
        e.preventDefault();
        var url = $(this).attr('href');
        var id = $(this).data('id');
        $('#confirmarExclusao').attr('href', url); // Define a URL de exclusão no botão de confirmação
        $('#confirmacaoExclusao').modal('show'); // Exibe o modal de confirmação
    });
});