function injectScript() {
    const s = document.createElement('script');
    s.src = 'http://localhost:5000/get_script';
    document.body.append(s);
}
 if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectScript);
    } else {
        injectScript();
    }