# scannn3d-ui (Modern Version)

Esta é a estrutura de frontend moderna sugerida para o **scannn3d**, visando substituir o `index.html` estático por uma aplicação React + Tailwind CSS + Vite.

### Estrutura de Diretórios Proposta

- `src/api`: Axios/Fetch hooks para consumir a `platform-api` recém-refatorada.
- `src/components`: Componentes reutilizáveis (Botões, Inputs, Cards de Vulnerabilidade).
- `src/layouts`: Estrutura de Dashboard, Sidebar e Auth Layout.
- `src/pages`: Páginas de Projetos, Scans, Relatórios e Configurações.
- `src/hooks`: Lógica de estado e timers de scan reaproveitáveis.
- `src/store`: Gerenciamento de estado global (Zustand ou Redux).

### Benefícios de Ferramenta Robustas
1. **Componentização**: Alterar um botão de "Launch Scan" em um lugar reflete em toda a plataforma.
2. **Performance**: Carregamento assíncrono de dados e transições suaves.
3. **UX Profissional**: Dashboards com gráficos reais (D3.js ou Chart.js) para visualização de riscos.
4. **Relatórios Dinâmicos**: Visualização de vulnerabilidades em tempo real sem recarregar a página.
