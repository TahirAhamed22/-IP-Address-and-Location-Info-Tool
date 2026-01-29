// ===== ENHANCED GLOBAL VARIABLES =====
let analysisEnabled = true;
let currentUserSalt = null;
let masterPasswordCache = null;
let securityMode = true;
let themePreference = 'dark';
let isLoginMode = true;
let vaultData = [];
let vaultFilter = '';
let vaultSortBy = 'updated_at';
let securityScore = 0;
let dashboardData = null;

let passwordGeneratorSettings = {
    length: 16,
    includeUpper: true,
    includeLower: true,
    includeNumbers: true,
    includeSymbols: true
};

let performanceMetrics = {
    pageLoadTime: 0,
    analysisCount: 0,
    apiCallCount: 0
};

// DOM Elements Storage
let elements = {};

// ===== ENHANCED INITIALIZATION =====
function initializeElements() {
    elements = {
        // Main interface elements
        themeToggle: document.getElementById('themeToggle'),
        passwordInput: document.getElementById('passwordInput'),
        strengthSection: document.getElementById('strengthSection'),
        analysisResults: document.getElementById('analysisResults'),
        policySection: document.getElementById('policySection'),
        strengthFill: document.getElementById('strengthFill'),
        strengthText: document.getElementById('strengthText'),
        crackTime: document.getElementById('crackTime'),
        breachStatus: document.getElementById('breachStatus'),
        entropyValue: document.getElementById('entropyValue'),
        lengthValue: document.getElementById('lengthValue'),
        
        // Policy icons
        lengthIcon: document.getElementById('lengthIcon'),
        lowerIcon: document.getElementById('lowerIcon'),
        upperIcon: document.getElementById('upperIcon'),
        digitIcon: document.getElementById('digitIcon'),
        symbolIcon: document.getElementById('symbolIcon'),
        
        // Input controls
        toggleVisibility: document.getElementById('toggleVisibility'),
        copyPassword: document.getElementById('copyPassword'),
        clearPassword: document.getElementById('clearPassword'),
        generatePassword: document.getElementById('generatePassword'),
        pauseBtn: document.getElementById('pauseBtn'),
        
        // Generator controls
        lengthSlider: document.getElementById('lengthSlider'),
        lengthValueDisplay: document.getElementById('lengthValue'),
        generateBtn: document.getElementById('generateBtn'),
        generatedPassword: document.getElementById('generatedPassword'),
        copyGenerated: document.getElementById('copyGenerated'),
        useGenerated: document.getElementById('useGenerated'),
        includeUpper: document.getElementById('includeUpper'),
        includeLower: document.getElementById('includeLower'),
        includeNumbers: document.getElementById('includeNumbers'),
        includeSymbols: document.getElementById('includeSymbols'),
        
        // Authentication elements
        authModal: document.getElementById('authModal'),
        authForm: document.getElementById('authForm'),
        authTitle: document.getElementById('authTitle'),
        authSubmit: document.getElementById('authSubmit'),
        authSwitchText: document.getElementById('authSwitchText'),
        authSwitchLink: document.getElementById('authSwitchLink'),
        authUsername: document.getElementById('authUsername'),
        authEmail: document.getElementById('authEmail'),
        authPhone: document.getElementById('authPhone'),
        authPassword: document.getElementById('authPassword'),
        loginBtn: document.getElementById('loginBtn'),
        loginPromptBtn: document.getElementById('loginPromptBtn'),
        closeModal: document.getElementById('closeModal'),
        
        // Vault elements
        vaultList: document.getElementById('vaultList'),
        savePasswordBtn: document.getElementById('save-password-btn'),
        siteName: document.getElementById('site-name'),
        vaultUsername: document.getElementById('vault-username'),
        vaultPassword: document.getElementById('vault-password'),
        vaultCategory: document.getElementById('vault-category'),
        vaultNotes: document.getElementById('vault-notes'),
        
        // Enhanced controls
        vaultSearch: document.getElementById('vault-search'),
        clearSearch: document.getElementById('clearSearch'),
        vaultSort: document.getElementById('vault-sort'),
        exportVault: document.getElementById('exportVault'),
        auditVault: document.getElementById('auditVault'),
        
        // Dashboard elements
        securityDashboardBtn: document.getElementById('securityDashboardBtn'),
        securityDashboard: document.getElementById('securityDashboard'),
        closeDashboard: document.getElementById('closeDashboard'),
        securityScoreValue: document.getElementById('securityScoreValue'),
        
        // Notification settings
        notificationSettingsBtn: document.getElementById('notificationSettingsBtn'),
        notificationSettingsModal: document.getElementById('notificationSettingsModal'),
        closeNotificationSettings: document.getElementById('closeNotificationSettings')
    };
}

async function initialize() {
    try {
        const pageLoadStart = performance.now();
        
        // Initialize DOM elements first
        initializeElements();
        
        // Check secure context
        checkSecureContext();
        
        // Initialize theme
        initializeTheme();
        
        // Add enhanced styles
        addEnhancedStyles();
        
        // Initialize event listeners
        initializeEventListeners();
        
        // Check authentication status
        await checkAuthenticationStatus();
        
        // Load vault data if authenticated
        if (currentUserSalt) {
            await loadVaultData();
            await loadSecurityDashboard();
        }
        
        // Initialize password generator
        initializePasswordGenerator();
        
        // Show security status
        showSecurityStatus();
        
        // Record performance metrics
        const pageLoadTime = performance.now() - pageLoadStart;
        recordPerformanceMetric('pageLoadTime', pageLoadTime);
        
        console.log(`VaultGuard Enhanced initialized in ${pageLoadTime.toFixed(2)}ms`);
        
    } catch (error) {
        console.error('Initialization error:', error);
        showNotification('Application failed to initialize properly', 'error');
    }
}

// ===== THEME MANAGEMENT =====
function initializeTheme() {
    const body = document.body;
    body.setAttribute('data-theme', themePreference);
    
    if (elements.themeToggle) {
        updateThemeToggleIcon();
        elements.themeToggle.addEventListener('click', toggleTheme);
    }
}

function toggleTheme() {
    themePreference = themePreference === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', themePreference);
    updateThemeToggleIcon();
    
    // Add smooth theme transition
    document.body.style.transition = 'all 0.3s ease';
    setTimeout(() => {
        document.body.style.transition = '';
    }, 300);
    
    showNotification(`Switched to ${themePreference} theme`, 'info');
}

function updateThemeToggleIcon() {
    if (elements.themeToggle) {
        elements.themeToggle.textContent = themePreference === 'dark' ? '🌙' : '☀️';
        elements.themeToggle.style.transform = 'scale(1.2)';
        setTimeout(() => {
            elements.themeToggle.style.transform = 'scale(1)';
        }, 200);
    }
}

// ===== ENHANCED EVENT LISTENERS =====
function initializeEventListeners() {
    // Password input analyzer
    if (elements.passwordInput) {
        elements.passwordInput.addEventListener('input', debounce((e) => {
            analyzePassword(e.target.value);
        }, 300));
        
        elements.passwordInput.addEventListener('focus', () => {
            if (elements.passwordInput.value) {
                analyzePassword(elements.passwordInput.value);
            }
        });
        
        elements.passwordInput.addEventListener('paste', (e) => {
            setTimeout(() => {
                analyzePassword(elements.passwordInput.value);
            }, 10);
        });
    }

    // Password control buttons
    setupPasswordControls();
    
    // Generator controls
    setupGeneratorControls();
    
    // Authentication controls
    setupAuthenticationControls();
    
    // Vault management
    setupVaultControls();
    
    // Enhanced search and sort
    setupEnhancedVaultControls();
    
    // Dashboard controls
    setupDashboardControls();
    
    // Security monitoring
    document.addEventListener('visibilitychange', handleVisibilityChange);
    document.addEventListener('keydown', handleKeyboardShortcuts);
}

function setupPasswordControls() {
    if (elements.toggleVisibility) {
        elements.toggleVisibility.addEventListener('click', togglePasswordVisibility);
    }
    if (elements.copyPassword) {
        elements.copyPassword.addEventListener('click', copyPasswordToClipboard);
    }
    if (elements.clearPassword) {
        elements.clearPassword.addEventListener('click', clearPasswordInput);
    }
    if (elements.generatePassword) {
        elements.generatePassword.addEventListener('click', generateAndAnalyzePassword);
    }
    if (elements.pauseBtn) {
        elements.pauseBtn.addEventListener('click', toggleAnalysis);
    }
}

function setupGeneratorControls() {
    if (elements.lengthSlider && elements.lengthValueDisplay) {
        elements.lengthSlider.addEventListener('input', (e) => {
            updateLengthDisplay(parseInt(e.target.value));
        });
    }
    
    if (elements.generateBtn) {
        elements.generateBtn.addEventListener('click', generateNewPassword);
    }
    
    if (elements.copyGenerated) {
        elements.copyGenerated.addEventListener('click', copyGeneratedPassword);
    }
    
    if (elements.useGenerated) {
        elements.useGenerated.addEventListener('click', useGeneratedPassword);
    }
    
    const checkboxes = [elements.includeUpper, elements.includeLower, elements.includeNumbers, elements.includeSymbols];
    checkboxes.forEach(checkbox => {
        if (checkbox) {
            checkbox.addEventListener('change', () => {
                updatePasswordGeneratorSettings();
                validateGeneratorSettings();
            });
        }
    });
}

function setupAuthenticationControls() {
    if (elements.loginBtn) {
        elements.loginBtn.addEventListener('click', (e) => {
            e.preventDefault();
            openAuthModal();
        });
    }
    
    if (elements.loginPromptBtn) {
        elements.loginPromptBtn.addEventListener('click', openAuthModal);
    }
    
    if (elements.closeModal) {
        elements.closeModal.addEventListener('click', closeAuthModal);
    }
    
    if (elements.authSwitchLink) {
        elements.authSwitchLink.addEventListener('click', (e) => {
            e.preventDefault();
            setAuthMode(!isLoginMode);
        });
    }
    
    if (elements.authForm) {
        elements.authForm.addEventListener('submit', handleAuth);
    }
    
    if (elements.authModal) {
        elements.authModal.addEventListener('click', (e) => {
            if (e.target === elements.authModal) {
                closeAuthModal();
            }
        });
    }
}

function setupVaultControls() {
    if (elements.savePasswordBtn) {
        elements.savePasswordBtn.addEventListener('click', savePassword);
    }
}

function setupEnhancedVaultControls() {
    if (elements.vaultSearch) {
        elements.vaultSearch.addEventListener('input', debounce((e) => {
            filterVaultEntries(e.target.value);
        }, 300));
        
        elements.vaultSearch.addEventListener('input', function() {
            if (elements.clearSearch) {
                elements.clearSearch.style.display = this.value.length > 0 ? 'block' : 'none';
            }
        });
    }
    
    if (elements.clearSearch) {
        elements.clearSearch.addEventListener('click', () => {
            elements.vaultSearch.value = '';
            elements.clearSearch.style.display = 'none';
            filterVaultEntries('');
            elements.vaultSearch.focus();
        });
    }
    
    if (elements.vaultSort) {
        elements.vaultSort.addEventListener('change', (e) => {
            sortVaultEntries(e.target.value);
        });
    }
    
    if (elements.exportVault) {
        elements.exportVault.addEventListener('click', exportVaultData);
    }
    
    if (elements.auditVault) {
        elements.auditVault.addEventListener('click', runSecurityAudit);
    }
}

function setupDashboardControls() {
    if (elements.securityDashboardBtn) {
        elements.securityDashboardBtn.addEventListener('click', toggleSecurityDashboard);
    }
    
    if (elements.closeDashboard) {
        elements.closeDashboard.addEventListener('click', () => {
            elements.securityDashboard.style.display = 'none';
        });
    }
}

// ===== ENHANCED PASSWORD ANALYSIS =====
function analyzePassword(password) {
    if (!password || !analysisEnabled) {
        hideAnalysisSection();
        resetPasswordPolicyIcons();
        resetStrengthMeter();
        return;
    }

    showAnalysisSection();
    
    // Enhanced strength calculation
    let score = 0;
    let strength = 'Critical Vulnerability';
    let strengthClass = 'critical';
    let recommendations = [];
    
    // Character type checks
    const hasLength = password.length >= 12;
    const hasMinLength = password.length >= 8;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);
    const hasLongLength = password.length >= 16;
    const hasExtraLength = password.length >= 20;
    const hasFortressLength = password.length >= 32;

    // Base scoring with enhanced weights
    if (hasMinLength) score += 10;
    if (hasLength) score += 15;
    if (hasLower) score += 10;
    if (hasUpper) score += 10;
    if (hasDigit) score += 10;
    if (hasSymbol) score += 20;
    if (hasLongLength) score += 15;
    if (hasExtraLength) score += 15;
    if (hasFortressLength) score += 20;

    // Advanced pattern analysis
    const analysis = performAdvancedPasswordAnalysis(password);
    score += analysis.bonusPoints;
    score -= analysis.penaltyPoints;
    recommendations = analysis.recommendations;

    // Ensure score is within bounds
    score = Math.max(0, Math.min(100, score));
    
    // Determine strength level
    const strengthLevels = [
        { min: 95, label: 'Fortress Grade', class: 'fortress' },
        { min: 85, label: 'Military Grade', class: 'military' },
        { min: 70, label: 'Strong', class: 'strong' },
        { min: 55, label: 'Good', class: 'good' },
        { min: 40, label: 'Fair', class: 'fair' },
        { min: 25, label: 'Weak', class: 'weak' },
        { min: 0, label: 'Critical Vulnerability', class: 'critical' }
    ];
    
    for (const level of strengthLevels) {
        if (score >= level.min) {
            strength = level.label;
            strengthClass = level.class;
            break;
        }
    }

    // Update UI
    updateStrengthMeter(score, strengthClass, strength);
    updateCrackTimeEstimate(score);
    updatePasswordPolicyIcons(hasLength, hasLower, hasUpper, hasDigit, hasSymbol);
    updatePasswordMetrics(password, score);
    
    // Check password against breach database
    checkPasswordStrengthAPI(password);
    
    // Show recommendations
    displayPasswordRecommendations(recommendations);
}

function performAdvancedPasswordAnalysis(password) {
    let bonusPoints = 0;
    let penaltyPoints = 0;
    let recommendations = [];
    
    // Common patterns that reduce security
    const commonPatterns = ['123', 'abc', 'qwe', 'pass', 'admin', 'user', 'login', 'welcome'];
    const keyboardPatterns = ['qwert', 'asdf', 'zxcv', 'yuiop', 'hjkl', 'bnm'];
    const weakSequences = ['1234', '4321', 'abcd', 'dcba'];
    
    const lowerPassword = password.toLowerCase();
    
    if (commonPatterns.some(pattern => lowerPassword.includes(pattern))) {
        penaltyPoints += 25;
        recommendations.push('Avoid common words like "password", "admin", "123"');
    }
    
    if (keyboardPatterns.some(pattern => lowerPassword.includes(pattern))) {
        penaltyPoints += 30;
        recommendations.push('Avoid keyboard patterns like "qwerty" or "asdf"');
    }
    
    if (weakSequences.some(seq => lowerPassword.includes(seq))) {
        penaltyPoints += 20;
        recommendations.push('Avoid sequential characters like "1234" or "abcd"');
    }
    
    // Check for repeated characters
    const repeatedChars = /(.)\1{2,}/.test(password);
    if (repeatedChars) {
        penaltyPoints += 20;
        recommendations.push('Avoid repeating the same character multiple times');
    }
    
    // Character diversity bonus
    const uniqueChars = new Set(password).size;
    const charsetDiversity = uniqueChars / password.length;
    
    if (charsetDiversity >= 0.8) {
        bonusPoints += 15;
    } else if (charsetDiversity >= 0.7) {
        bonusPoints += 10;
    } else if (charsetDiversity < 0.5) {
        penaltyPoints += 10;
        recommendations.push('Use more diverse characters');
    }
    
    // Date pattern detection
    const currentYear = new Date().getFullYear();
    const yearPattern = new RegExp(`(${currentYear}|${currentYear-1}|${currentYear-2}|19\\d\\d|20\\d\\d)`);
    if (yearPattern.test(password)) {
        penaltyPoints += 15;
        recommendations.push('Avoid using years or dates in passwords');
    }
    
    // Length bonuses
    if (password.length >= 24) bonusPoints += 10;
    if (password.length >= 28) bonusPoints += 10;
    if (password.length >= 40) bonusPoints += 15;
    
    return {
        bonusPoints,
        penaltyPoints,
        recommendations: recommendations.slice(0, 3)
    };
}

function resetStrengthMeter() {
    if (elements.strengthFill) {
        elements.strengthFill.style.width = '0%';
        elements.strengthFill.className = 'strength-fill';
        elements.strengthFill.style.animation = '';
        elements.strengthFill.style.boxShadow = '';
    }
    
    if (elements.strengthText) {
        elements.strengthText.textContent = '-';
        elements.strengthText.className = 'strength-text';
    }
    
    if (elements.crackTime) {
        elements.crackTime.textContent = '-';
    }
    
    if (elements.breachStatus) {
        elements.breachStatus.innerHTML = '-';
    }
    
    if (elements.entropyValue) {
        elements.entropyValue.textContent = '- bits';
    }
    
    if (elements.lengthValue) {
        elements.lengthValue.textContent = '- chars';
    }
}

function updatePasswordMetrics(password, score) {
    // Update entropy display
    if (elements.entropyValue) {
        const entropy = calculateEntropy(password);
        elements.entropyValue.textContent = `${entropy.toFixed(1)} bits`;
        elements.entropyValue.style.animation = 'fadeIn 0.4s ease-out';
    }
    
    // Update length display
    if (elements.lengthValue) {
        elements.lengthValue.textContent = `${password.length} chars`;
        elements.lengthValue.style.animation = 'fadeIn 0.4s ease-out';
    }
}

function calculateEntropy(password) {
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
    
    return Math.log2(Math.pow(charsetSize, password.length));
}

// ===== ENHANCED UI UPDATE FUNCTIONS =====
function updateStrengthMeter(score, strengthClass, strength) {
    if (elements.strengthFill) {
        elements.strengthFill.style.width = score + '%';
        
        // Remove all previous strength classes
        const strengthClasses = ['critical', 'weak', 'fair', 'good', 'strong', 'military', 'fortress'];
        elements.strengthFill.classList.remove(...strengthClasses);
        elements.strengthFill.classList.add(strengthClass);
        
        // Add pulsing animation for high-security passwords
        if (score >= 85) {
            elements.strengthFill.style.animation = 'strengthPulse 2s ease-in-out infinite';
        } else {
            elements.strengthFill.style.animation = '';
        }
    }
    
    if (elements.strengthText) {
        elements.strengthText.textContent = strength;
        elements.strengthText.className = `strength-text ${strengthClass}`;
        elements.strengthText.style.animation = 'fadeIn 0.3s ease-out';
    }
}

function updateCrackTimeEstimate(score) {
    const crackTimes = [
        'instantly', 'milliseconds', 'seconds', 'minutes', 
        'hours', 'days', 'weeks', 'months', 'years', 
        'decades', 'centuries', 'millennia', 'geological ages'
    ];
    
    const timeIndex = Math.min(Math.floor(score / 8), crackTimes.length - 1);
    
    if (elements.crackTime) {
        elements.crackTime.textContent = crackTimes[timeIndex];
        elements.crackTime.style.animation = 'fadeIn 0.4s ease-out';
    }
}

function updatePasswordPolicyIcons(hasLength, hasLower, hasUpper, hasDigit, hasSymbol) {
    updatePolicyIcon(elements.lengthIcon, hasLength);
    updatePolicyIcon(elements.lowerIcon, hasLower);
    updatePolicyIcon(elements.upperIcon, hasUpper);
    updatePolicyIcon(elements.digitIcon, hasDigit);
    updatePolicyIcon(elements.symbolIcon, hasSymbol);
}

function updatePolicyIcon(icon, isValid) {
    if (!icon) return;
    
    icon.style.transition = 'all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275)';
    
    if (isValid) {
        icon.className = 'policy-icon valid';
        icon.textContent = '✓';
        icon.style.color = '#2ed573';
        icon.style.backgroundColor = 'rgba(46, 213, 115, 0.15)';
        icon.style.border = '2px solid rgba(46, 213, 115, 0.3)';
        icon.style.transform = 'scale(1.1)';
        
        setTimeout(() => { 
            icon.style.transform = 'scale(1)'; 
        }, 200);
    } else {
        icon.className = 'policy-icon invalid';
        icon.textContent = '✗';
        icon.style.color = '#ff4757';
        icon.style.backgroundColor = 'rgba(255, 71, 87, 0.15)';
        icon.style.border = '2px solid rgba(255, 71, 87, 0.3)';
    }
}

function resetPasswordPolicyIcons() {
    const icons = [elements.lengthIcon, elements.lowerIcon, elements.upperIcon, elements.digitIcon, elements.symbolIcon];
    icons.forEach(icon => {
        if (icon) {
            icon.className = 'policy-icon';
            icon.textContent = '○';
            icon.style.color = '#6c757d';
            icon.style.backgroundColor = 'rgba(108, 117, 125, 0.1)';
        }
    });
}

function showAnalysisSection() {
    if (elements.strengthSection) {
        elements.strengthSection.style.display = 'block';
        elements.strengthSection.style.animation = 'fadeIn 0.3s ease-out';
    }
    if (elements.analysisResults) {
        elements.analysisResults.style.display = 'grid';
        elements.analysisResults.style.animation = 'fadeIn 0.4s ease-out';
    }
    if (elements.policySection) {
        elements.policySection.style.display = 'block';
        elements.policySection.style.animation = 'fadeIn 0.5s ease-out';
    }
}

function hideAnalysisSection() {
    const sections = [elements.strengthSection, elements.analysisResults, elements.policySection];
    sections.forEach(section => {
        if (section) {
            section.style.display = 'none';
            section.style.animation = '';
        }
    });
    
    const recommendationsElement = document.getElementById('passwordRecommendations');
    if (recommendationsElement) {
        recommendationsElement.style.display = 'none';
    }
}

function displayPasswordRecommendations(recommendations) {
    const recommendationsElement = document.getElementById('passwordRecommendations');
    if (recommendationsElement && recommendations.length > 0) {
        recommendationsElement.innerHTML = `
            <div class="recommendations-header">💡 Security Recommendations:</div>
            <ul class="recommendations-list">
                ${recommendations.map(rec => `<li>${rec}</li>`).join('')}
            </ul>
        `;
        recommendationsElement.style.display = 'block';
        recommendationsElement.style.animation = 'fadeIn 0.5s ease-out';
    } else if (recommendationsElement) {
        recommendationsElement.style.display = 'none';
    }
}

// ===== ENHANCED BREACH CHECKING =====
async function checkPasswordStrengthAPI(password) {
    try {
        performanceMetrics.apiCallCount++;
        
        const response = await fetch('/api/check_password', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ password: password })
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                updateBreachStatus(data.breached, data.count, data.security_level);
                updateAdvancedMetrics(data);
            }
        } else {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
    } catch (error) {
        console.error('Password strength check failed:', error);
        if (elements.breachStatus) {
            elements.breachStatus.innerHTML = '<span style="color: var(--text-secondary);">⚠️ Unable to check breach status</span>';
        }
    }
}

function updateBreachStatus(isBreached, count, securityLevel) {
    if (!elements.breachStatus) return;
    
    if (isBreached) {
        let warningLevel = 'COMPROMISED';
        let warningColor = '#ff4757';
        
        switch (securityLevel) {
            case 'critical':
                warningLevel = 'CRITICAL RISK';
                warningColor = '#ff4757';
                break;
            case 'high_risk':
                warningLevel = 'HIGH RISK';
                warningColor = '#ff6348';
                break;
            case 'medium_risk':
                warningLevel = 'MEDIUM RISK';
                warningColor = '#ffa502';
                break;
            default:
                warningLevel = 'COMPROMISED';
                warningColor = '#ff4757';
        }
        
        elements.breachStatus.innerHTML = `
            <span class="breach-warning" style="color: ${warningColor}; animation: breachPulse 1.5s ease-in-out infinite; font-weight: 700;">
                🚨 ${warningLevel}: Found in ${count.toLocaleString()} breaches!
            </span>`;
    } else {
        let securityText = 'SECURE';
        let securityColor = '#2ed573';
        
        switch (securityLevel) {
            case 'fortress':
                securityText = 'FORTRESS LEVEL';
                securityColor = '#2ed573';
                break;
            case 'military':
                securityText = 'MILITARY GRADE';
                securityColor = '#58a6ff';
                break;
            case 'strong':
                securityText = 'STRONG SECURITY';
                securityColor = '#2ed573';
                break;
            default:
                securityText = 'SECURE';
                securityColor = '#2ed573';
        }
        
        elements.breachStatus.innerHTML = `
            <span class="breach-safe" style="color: ${securityColor}; font-weight: 700;">
                ✅ ${securityText}: Not found in known breaches
            </span>`;
    }
}

function updateAdvancedMetrics(data) {
    // Update additional metrics if available
    if (data.entropy && elements.entropyValue) {
        elements.entropyValue.textContent = `${data.entropy.toFixed(1)} bits`;
    }
}

// ===== PASSWORD CONTROL FUNCTIONS =====
function togglePasswordVisibility() {
    if (!elements.passwordInput || !elements.toggleVisibility) return;
    
    const type = elements.passwordInput.type === 'password' ? 'text' : 'password';
    elements.passwordInput.type = type;
    elements.toggleVisibility.textContent = type === 'password' ? '👁️' : '🙈';
    elements.toggleVisibility.style.transform = 'scale(1.1)';
    
    setTimeout(() => { 
        elements.toggleVisibility.style.transform = 'scale(1)'; 
    }, 150);
}

async function copyPasswordToClipboard() {
    if (!elements.passwordInput?.value) {
        showNotification('No password to copy', 'warning');
        return;
    }
    
    try {
        await navigator.clipboard.writeText(elements.passwordInput.value);
        showNotification('Password copied securely!', 'success');
        
        // Security: Clear clipboard after 30 seconds
        setTimeout(() => {
            navigator.clipboard.writeText('').catch(() => {});
        }, 30000);
    } catch (err) {
        console.error('Clipboard error:', err);
        showNotification('Failed to copy password', 'error');
    }
}

function clearPasswordInput() {
    if (elements.passwordInput) {
        elements.passwordInput.value = '';
        analyzePassword('');
        elements.passwordInput.focus();
        showNotification('Password cleared securely', 'info');
    }
}

function generateAndAnalyzePassword() {
    const generatedPwd = generateRandomPassword();
    if (elements.passwordInput) {
        elements.passwordInput.value = generatedPwd;
        analyzePassword(generatedPwd);
        showNotification('Secure password generated and analyzed!', 'success');
    }
}

function toggleAnalysis() {
    analysisEnabled = !analysisEnabled;
    
    if (elements.pauseBtn) {
        elements.pauseBtn.textContent = analysisEnabled ? '⏸️' : '▶️';
        elements.pauseBtn.title = analysisEnabled ? 'Pause analysis' : 'Resume analysis';
        elements.pauseBtn.style.transform = 'scale(1.1)';
        setTimeout(() => { elements.pauseBtn.style.transform = 'scale(1)'; }, 150);
    }
    
    if (!analysisEnabled) {
        hideAnalysisSection();
        showNotification('Password analysis paused', 'info');
    } else {
        analyzePassword(elements.passwordInput?.value || '');
        showNotification('Password analysis resumed', 'info');
    }
}

// ===== ENHANCED AUTHENTICATION =====
function openAuthModal() {
    if (elements.authModal) {
        elements.authModal.classList.add('show');
        elements.authModal.style.animation = 'modalFadeIn 0.3s ease-out';
        setAuthMode(isLoginMode);
        
        // Focus on username field
        setTimeout(() => {
            if (elements.authUsername) {
                elements.authUsername.focus();
            }
        }, 100);
    }
}

function closeAuthModal() {
    if (elements.authModal) {
        elements.authModal.style.animation = 'modalFadeOut 0.3s ease-out';
        setTimeout(() => {
            elements.authModal.classList.remove('show');
        }, 300);
        
        // Reset form
        if (elements.authForm) {
            elements.authForm.reset();
        }
        
        // Clear any error states
        clearAuthErrors();
    }
}

function setAuthMode(loginMode) {
    isLoginMode = loginMode;
    
    if (elements.authTitle && elements.authSubmit && elements.authSwitchText && elements.authSwitchLink) {
        if (isLoginMode) {
            elements.authTitle.textContent = '🔐 VaultGuard Secure Access';
            elements.authSubmit.textContent = 'Secure Login';
            elements.authSwitchText.textContent = "Don't have an account?";
            elements.authSwitchLink.textContent = 'Create Account';
            
            // Hide optional fields for login
            if (elements.authEmail) elements.authEmail.style.display = 'none';
            if (elements.authPhone) elements.authPhone.style.display = 'none';
        } else {
            elements.authTitle.textContent = '🛡️ Create Secure Account';
            elements.authSubmit.textContent = 'Create Account';
            elements.authSwitchText.textContent = 'Already have an account?';
            elements.authSwitchLink.textContent = 'Login';
            
            // Show optional fields for registration
            if (elements.authEmail) elements.authEmail.style.display = 'block';
            if (elements.authPhone) elements.authPhone.style.display = 'block';
        }
    }
    
    // Clear any previous errors
    clearAuthErrors();
}

function clearAuthErrors() {
    const errorElements = document.querySelectorAll('.auth-error');
    errorElements.forEach(el => el.remove());
    
    // Reset input field styles
    [elements.authUsername, elements.authEmail, elements.authPhone, elements.authPassword].forEach(input => {
        if (input) {
            input.style.borderColor = '';
            input.classList.remove('error');
        }
    });
}

function showAuthError(message, targetElement = null) {
    clearAuthErrors();
    
    const errorDiv = document.createElement('div');
    errorDiv.className = 'auth-error';
    errorDiv.style.cssText = `
        color: #ff4757;
        background: rgba(255, 71, 87, 0.1);
        border: 1px solid rgba(255, 71, 87, 0.3);
        padding: 0.75rem;
        border-radius: 6px;
        margin-top: 0.5rem;
        font-size: 0.9rem;
        animation: fadeIn 0.3s ease-out;
    `;
    errorDiv.textContent = message;
    
    if (targetElement && targetElement.parentNode) {
        targetElement.parentNode.appendChild(errorDiv);
        targetElement.style.borderColor = '#ff4757';
        targetElement.classList.add('error');
    } else if (elements.authForm) {
        elements.authForm.appendChild(errorDiv);
    }
}

async function handleAuth(event) {
    event.preventDefault();
    
    const username = elements.authUsername?.value.trim();
    const email = elements.authEmail?.value.trim();
    const phone = elements.authPhone?.value.trim();
    const password = elements.authPassword?.value;
    
    // Basic validation
    if (!username || !password) {
        showAuthError('Please fill in required fields');
        return;
    }
    
    // Registration-specific validation
    if (!isLoginMode) {
        if (username.length < 3) {
            showAuthError('Username must be at least 3 characters long', elements.authUsername);
            return;
        }
        
        if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
            showAuthError('Username can only contain letters, numbers, dots, hyphens, and underscores', elements.authUsername);
            return;
        }
        
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            showAuthError('Please enter a valid email address', elements.authEmail);
            return;
        }
        
        if (password.length < 12) {
            showAuthError('Password must be at least 12 characters long for security', elements.authPassword);
            return;
        }
        
        const passwordValidation = validatePasswordComplexity(password);
        if (!passwordValidation.isValid) {
            showAuthError(passwordValidation.message, elements.authPassword);
            return;
        }
    }
    
    const endpoint = isLoginMode ? '/api/login' : '/api/register';
    const requestData = isLoginMode 
        ? { username, password }
        : { username, password, email: email || undefined, phone: phone || undefined };
    
    try {
        // Update submit button state
        updateAuthSubmitState(true);
        
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(requestData)
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUserSalt = data.salt;
            masterPasswordCache = password;
            securityScore = data.security_score || 0;

            // ✅ FIX: Show AI threat alert if present
            if (data.ai_threat_analysis) {
                handleAIThreatAlert(data.ai_threat_analysis);
            }

            // 🔥 NEW: Check for 2FA requirement
            if (data.force_2fa) {
                show2FAModal();
                return; // Stop here, wait for 2FA verification
            }

            // Handle new device notification
            if (data.new_device) {
                showNotification('New device detected! Check your notifications for security alert.', 'warning');
            }
            
            showNotification(data.message, 'success');
            closeAuthModal();
            
            // Smooth transition to authenticated state
            setTimeout(() => {
                window.location.reload();
            }, 1500);
        } else {
            showAuthError(data.message);
        }
    } catch (error) {
        console.error('Auth error:', error);
        showAuthError('Network error. Please check your connection and try again.');
    } finally {
        updateAuthSubmitState(false);
    }
}

function validatePasswordComplexity(password) {
    const requirements = [];
    
    if (!/[a-z]/.test(password)) requirements.push('lowercase letter');
    if (!/[A-Z]/.test(password)) requirements.push('uppercase letter');
    if (!/[0-9]/.test(password)) requirements.push('number');
    if (!/[!@#$%^&*()_+-=\[\]{}|;:,.<>?]/.test(password)) requirements.push('special character');
    
    if (requirements.length > 0) {
        return {
            isValid: false,
            message: `Password must contain: ${requirements.join(', ')}`
        };
    }
    
    return { isValid: true, message: '' };
}

function updateAuthSubmitState(isLoading) {
    if (!elements.authSubmit) return;
    
    if (isLoading) {
        elements.authSubmit.disabled = true;
        elements.authSubmit.textContent = isLoginMode ? 'Authenticating...' : 'Creating Account...';
        elements.authSubmit.style.opacity = '0.7';
        elements.authSubmit.style.cursor = 'not-allowed';
    } else {
        elements.authSubmit.disabled = false;
        elements.authSubmit.textContent = isLoginMode ? 'Secure Login' : 'Create Account';
        elements.authSubmit.style.opacity = '1';
        elements.authSubmit.style.cursor = 'pointer';
    }
}

// ===== ENHANCED VAULT MANAGEMENT =====
async function checkAuthenticationStatus() {
    try {
        const response = await fetch('/api/me', {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        const data = await response.json();
        
        if (data.success && data.authenticated) {
            currentUserSalt = data.salt;
            securityScore = data.security_score || 0;
            updateUIForAuthenticatedUser(data);
        } else {
            updateUIForUnauthenticatedUser();
        }
    } catch (error) {
        console.error('Failed to check auth status:', error);
        updateUIForUnauthenticatedUser();
    }
}

function updateUIForAuthenticatedUser(userData) {
    // Update security score display
    if (elements.securityScoreValue) {
        elements.securityScoreValue.textContent = userData.security_score || 0;
        
        // Update color based on score
        const scoreElement = elements.securityScoreValue.parentElement;
        if (scoreElement) {
            scoreElement.className = 'security-score-badge';
            if (userData.security_score >= 80) {
                scoreElement.classList.add('excellent');
            } else if (userData.security_score >= 60) {
                scoreElement.classList.add('good');
            } else if (userData.security_score >= 40) {
                scoreElement.classList.add('fair');
            } else {
                scoreElement.classList.add('poor');
            }
        }
    }
    
    // Show password age warning if needed
    if (userData.password_age_warning) {
        setTimeout(() => {
            showNotification('Your master password is over 90 days old. Consider changing it for better security.', 'warning');
        }, 3000);
    }
}

function updateUIForUnauthenticatedUser() {
    currentUserSalt = null;
    masterPasswordCache = null;
    securityScore = 0;
}

async function loadVaultData() {
    try {
        showLoadingState('vault');
        
        const response = await fetch('/api/vault', {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                vaultData = data.vault_entries;
                securityScore = data.security_score || securityScore;
                updateVaultDisplay();
                showNotification(`Loaded ${vaultData.length} encrypted passwords`, 'info');
                
                // Update security score
                if (elements.securityScoreValue) {
                    elements.securityScoreValue.textContent = securityScore;
                }
            }
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (error) {
        console.error('Failed to load vault data:', error);
        showNotification('Failed to load vault data', 'error');
    } finally {
        hideLoadingState('vault');
    }
}

async function savePassword() {
    const site = elements.siteName?.value.trim();
    const username = elements.vaultUsername?.value.trim();
    const password = elements.vaultPassword?.value;
    const category = elements.vaultCategory?.value || 'General';
    const notes = elements.vaultNotes?.value.trim();
    
    // Validation
    if (!site || !username || !password) {
        showNotification('Please fill in all required fields', 'error');
        highlightEmptyFields([elements.siteName, elements.vaultUsername, elements.vaultPassword]);
        return;
    }
    
    if (site.length > 120) {
        showNotification('Site name must be less than 120 characters', 'error');
        return;
    }
    
    if (username.length > 120) {
        showNotification('Username must be less than 120 characters', 'error');
        return;
    }
    
    const masterPassword = await getMasterPassword();
    if (!masterPassword) return;
    
    try {
        updateSaveButtonState(true);
        
        const response = await fetch('/api/vault', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({
                site: site,
                username: username,
                password: password,
                category: category,
                notes: notes,
                master_password: masterPassword
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Clear form
            elements.siteName.value = '';
            elements.vaultUsername.value = '';
            elements.vaultPassword.value = '';
            elements.vaultNotes.value = '';
            elements.vaultCategory.value = 'General';
            
            // Show breach warning if needed
            if (data.breach_warning) {
                showNotification(`⚠️ Password saved but found in ${data.breach_count?.toLocaleString()} breaches! Consider changing it.`, 'warning');
            } else {
                showNotification(data.message, 'success');
            }
            
            // Reload vault data
            await loadVaultData();
            
            // Focus back to site field for next entry
            elements.siteName.focus();
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Failed to save password:', error);
        showNotification('Failed to save password. Please try again.', 'error');
    } finally {
        updateSaveButtonState(false);
    }
}

function highlightEmptyFields(fields) {
    fields.forEach(field => {
        if (field && !field.value.trim()) {
            field.style.borderColor = '#ff4757';
            field.style.animation = 'shake 0.5s ease-in-out';
            
            setTimeout(() => {
                field.style.borderColor = '';
                field.style.animation = '';
            }, 2000);
        }
    });
}

function updateSaveButtonState(isLoading) {
    if (!elements.savePasswordBtn) return;
    
    if (isLoading) {
        elements.savePasswordBtn.disabled = true;
        elements.savePasswordBtn.textContent = 'Encrypting & Saving...';
        elements.savePasswordBtn.style.opacity = '0.7';
    } else {
        elements.savePasswordBtn.disabled = false;
        elements.savePasswordBtn.textContent = '💾 Encrypt & Store Securely';
        elements.savePasswordBtn.style.opacity = '1';
    }
}

async function getMasterPassword() {
    if (masterPasswordCache) {
        return masterPasswordCache;
    }
    
    const password = prompt('🔐 Enter your master password to access secure vault:');
    if (!password) {
        showNotification('Master password required for vault access', 'warning');
        return null;
    }
    
    // Cache password for 5 minutes
    masterPasswordCache = password;
    setTimeout(() => { 
        masterPasswordCache = null;
        showNotification('Master password session expired for security', 'info');
    }, 5 * 60 * 1000);
    
    return password;
}

// ===== ENHANCED VAULT DISPLAY =====
function updateVaultDisplay() {
    if (!elements.vaultList) return;
    
    let filteredData = vaultData;
    
    // Apply filter
    if (vaultFilter) {
        filteredData = vaultData.filter(item => 
            item.site.toLowerCase().includes(vaultFilter) ||
            item.username.toLowerCase().includes(vaultFilter) ||
            item.category.toLowerCase().includes(vaultFilter) ||
            (item.notes && item.notes.toLowerCase().includes(vaultFilter))
        );
    }
    
    // Apply sorting
    filteredData.sort((a, b) => {
        switch (vaultSortBy) {
            case 'site':
                return a.site.localeCompare(b.site);
            case 'username':
                return a.username.localeCompare(b.username);
            case 'category':
                return a.category.localeCompare(b.category);
            case 'created_at':
                return new Date(b.created_at) - new Date(a.created_at);
            case 'access_count':
                return (b.access_count || 0) - (a.access_count || 0);
            case 'updated_at':
            default:
                return new Date(b.updated_at) - new Date(a.updated_at);
        }
    });
    
    if (filteredData.length === 0) {
        displayEmptyVault();
        return;
    }
    
    // Display vault statistics
    displayVaultStats(filteredData.length);
    
    // Display vault entries
    elements.vaultList.innerHTML = filteredData.map((item, index) => {
        const strengthClass = getStrengthClass(item.strength_score);
        const compromisedStatus = item.is_compromised ? '🚨 Compromised' : '';
        const lastAccessed = item.last_accessed ? formatTimestamp(item.last_accessed) : 'Never';
        
        return `
            <li class="vault-item ${item.is_compromised ? 'compromised' : ''}" style="animation: fadeInUp 0.4s ease-out ${index * 0.05}s backwards;">
                <div class="vault-info">
                    <div class="site-header">
                        <h4 class="site-name">${escapeHtml(item.site)}</h4>
                        <div class="vault-meta">
                            <span class="category-badge">${escapeHtml(item.category)}</span>
                            <span class="created-date">Added: ${formatTimestamp(item.created_at)}</span>
                            ${item.updated_at !== item.created_at ? `<span class="updated-badge">Updated</span>` : ''}
                        </div>
                    </div>
                    <p class="username-display">👤 ${escapeHtml(item.username)}</p>
                    <div class="password-preview">🔐 Password: ••••••••••• (AES-256 Encrypted)</div>
                    
                    <div class="security-indicators">
                        <span class="strength-indicator ${strengthClass}">
                            Strength: ${item.strength_score || 0}%
                        </span>
                        ${item.is_compromised ? '<span class="compromised-indicator">⚠️ Compromised</span>' : ''}
                    </div>
                    
                    ${item.notes ? `<div class="password-notes">📝 ${escapeHtml(item.notes)}</div>` : ''}
                    
                    <div class="access-info">
                        <span class="access-count">Accessed: ${item.access_count || 0} times</span>
                        <span class="last-accessed">Last: ${lastAccessed}</span>
                    </div>
                    
                    ${item.updated_at !== item.created_at ? `<div class="updated-date">Last updated: ${formatTimestamp(item.updated_at)}</div>` : ''}
                </div>
                <div class="vault-actions">
                    <button id="copy-btn-${item.id}" class="vault-btn copy-btn" onclick="copyVaultPassword(${item.id})" title="Secure copy">
                        📋 <span>Copy</span>
                    </button>
                    <button id="view-btn-${item.id}" class="vault-btn view-btn" onclick="viewVaultPassword(${item.id})" title="Decrypt & view">
                        👁️ <span>View</span>
                    </button>
                    <button id="edit-btn-${item.id}" class="vault-btn edit-btn" onclick="editVaultPassword(${item.id})" title="Edit entry">
                        ✏️ <span>Edit</span>
                    </button>
                    <button id="delete-btn-${item.id}" class="vault-btn delete-btn" onclick="deleteVaultPassword(${item.id})" title="Secure delete">
                        🗑️ <span>Delete</span>
                    </button>
                </div>
            </li>
        `;
    }).join('');
}

function getStrengthClass(score) {
    if (score >= 80) return 'excellent';
    if (score >= 60) return 'good';
    if (score >= 40) return 'fair';
    return 'poor';
}

function displayEmptyVault() {
    if (vaultFilter) {
        elements.vaultList.innerHTML = `
            <li class="empty-vault">
                <div class="empty-vault-content">
                    <div style="font-size: 3rem; margin-bottom: 1rem;">🔍</div>
                    <h3>No Results Found</h3>
                    <p>No passwords match your search for "${vaultFilter}"</p>
                    <button onclick="clearVaultFilter()" class="clear-filter-btn">Clear Filter</button>
                </div>
            </li>`;
    } else {
        elements.vaultList.innerHTML = `
            <li class="empty-vault">
                <div class="empty-vault-content">
                    <div style="font-size: 4rem; margin-bottom: 1rem;">🔐</div>
                    <h3>Your Secure Vault is Empty</h3>
                    <p>Add your first password to experience military-grade encryption!</p>
                    <div class="security-reminder">
                        <strong>Enhanced Features:</strong> Smart notifications, breach detection, security audit, and more!
                    </div>
                    <div class="security-features">
                        <div class="feature">🛡️ AES-256 + PBKDF2</div>
                        <div class="feature">🔍 Real-time Breach Check</div>
                        <div class="feature">📧 Smart Notifications</div>
                        <div class="feature">📊 Security Dashboard</div>
                        <div class="feature">🔑 Password Recovery</div>
                        <div class="feature">🚫 Zero-Knowledge</div>
                    </div>
                </div>
            </li>`;
    }
}

function displayVaultStats(visibleCount) {
    // Remove existing stats
    const existingStats = document.querySelector('.vault-stats');
    if (existingStats) {
        existingStats.remove();
    }
    
    const compromisedCount = vaultData.filter(item => item.is_compromised).length;
    const weakCount = vaultData.filter(item => (item.strength_score || 0) < 50).length;
    const strongCount = vaultData.filter(item => (item.strength_score || 0) >= 80).length;
    
    const statsDiv = document.createElement('div');
    statsDiv.className = 'vault-stats';
    statsDiv.innerHTML = `
        <div class="stats-grid">
            <div class="stat-item">
                <span class="stat-value">${visibleCount}</span>
                <span class="stat-label">${vaultFilter ? 'Filtered' : 'Total'} Passwords</span>
            </div>
            <div class="stat-item ${strongCount > 0 ? 'good' : ''}">
                <span class="stat-value">${strongCount}</span>
                <span class="stat-label">Strong (80%+)</span>
            </div>
            <div class="stat-item ${compromisedCount > 0 ? 'critical' : 'good'}">
                <span class="stat-value">${compromisedCount}</span>
                <span class="stat-label">Compromised</span>
            </div>
            <div class="stat-item ${weakCount > 0 ? 'warning' : 'good'}">
                <span class="stat-value">${weakCount}</span>
                <span class="stat-label">Weak (<50%)</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">${50 - vaultData.length}</span>
                <span class="stat-label">Remaining Slots</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">${securityScore}%</span>
                <span class="stat-label">Security Score</span>
            </div>
        </div>
    `;
    
    if (elements.vaultList && elements.vaultList.parentNode) {
        elements.vaultList.parentNode.insertBefore(statsDiv, elements.vaultList);
    }
}

function filterVaultEntries(searchTerm) {
    vaultFilter = searchTerm.toLowerCase();
    updateVaultDisplay();
}

function sortVaultEntries(sortBy) {
    vaultSortBy = sortBy;
    updateVaultDisplay();
}

function clearVaultFilter() {
    vaultFilter = '';
    if (elements.vaultSearch) {
        elements.vaultSearch.value = '';
    }
    if (elements.clearSearch) {
        elements.clearSearch.style.display = 'none';
    }
    updateVaultDisplay();
}

// ===== VAULT OPERATIONS =====
async function copyVaultPassword(id) {
    const masterPassword = await getMasterPassword();
    if (!masterPassword) return;
    
    try {
        showButtonLoading(`copy-btn-${id}`, 'Copying...');
        
        const response = await fetch(`/api/vault/${id}/password`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ master_password: masterPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
            await navigator.clipboard.writeText(data.password);
            showNotification('Password securely copied to clipboard!', 'success');
            
            // Security: Clear clipboard after 30 seconds
            setTimeout(() => {
                navigator.clipboard.writeText('').catch(() => {});
            }, 30000);
            
            // Update access count
            await loadVaultData();
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Failed to copy password:', error);
        showNotification('Failed to copy password', 'error');
    } finally {
        hideButtonLoading(`copy-btn-${id}`, '📋 Copy');
    }
}

async function viewVaultPassword(id) {
    const masterPassword = await getMasterPassword();
    if (!masterPassword) return;
    
    try {
        showButtonLoading(`view-btn-${id}`, 'Decrypting...');
        
        const response = await fetch(`/api/vault/${id}/password`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ master_password: masterPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
            const item = vaultData.find(item => item.id === id);
            displayPasswordModal(item, data.password);
            
            // Update access count
            await loadVaultData();
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Failed to view password:', error);
        showNotification('Failed to decrypt password', 'error');
    } finally {
        hideButtonLoading(`view-btn-${id}`, '👁️ View');
    }
}

function editVaultPassword(id) {
    const item = vaultData.find(item => item.id === id);
    if (!item) return;
    
    // Populate the form with existing data
    elements.siteName.value = item.site;
    elements.vaultUsername.value = item.username;
    elements.vaultCategory.value = item.category || 'General';
    elements.vaultNotes.value = item.notes || '';
    
    // Focus on password field for editing
    elements.vaultPassword.focus();
    elements.vaultPassword.placeholder = 'Enter new password (leave empty to keep current)';
    
    showNotification('Edit mode: Update the fields and save to modify this entry', 'info');
    
    // Scroll to form
    elements.siteName.scrollIntoView({ behavior: 'smooth' });
}

async function deleteVaultPassword(id) {
    const item = vaultData.find(item => item.id === id);
    if (!item) return;
    
    if (!confirm(`⚠️ Permanently delete password for "${item.site}"?\n\nThis action cannot be undone and will remove the encrypted data.`)) {
        return;
    }
    
    try {
        showButtonLoading(`delete-btn-${id}`, 'Deleting...');
        
        const response = await fetch(`/api/vault/${id}`, {
            method: 'DELETE',
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            await loadVaultData();
            showNotification('Password securely deleted', 'success');
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Failed to delete password:', error);
        showNotification('Failed to delete password', 'error');
    } finally {
        hideButtonLoading(`delete-btn-${id}`, '🗑️ Delete');
    }
}

// ===== SECURITY DASHBOARD =====
async function toggleSecurityDashboard() {
    if (!elements.securityDashboard) return;
    
    if (elements.securityDashboard.style.display === 'none' || !elements.securityDashboard.style.display) {
        await loadSecurityDashboard();
    } else {
        elements.securityDashboard.style.display = 'none';
    }
}

async function loadSecurityDashboard() {
    try {
        const response = await fetch('/api/security/dashboard', {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            dashboardData = data.dashboard;
            updateDashboardDisplay(dashboardData);
            elements.securityDashboard.style.display = 'block';
            
            // 🔥 ADD THIS ONE LINE
            await loadAIThreatStats();
        } else {
            showNotification('Failed to load security dashboard', 'error');
        }
    } catch (error) {
        console.error('Dashboard error:', error);
        showNotification('Network error loading dashboard', 'error');
    }
}

function updateDashboardDisplay(dashboard) {
    // Update metrics
    const metrics = {
        securityScoreMetric: dashboard.security_score,
        totalPasswordsMetric: dashboard.total_passwords,
        compromisedMetric: dashboard.compromised_passwords,
        weakMetric: dashboard.weak_passwords
    };
    
    Object.entries(metrics).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
            element.style.animation = 'fadeIn 0.5s ease-out';
        }
    });
    
    // Update security trend
    const trendElement = document.getElementById('securityTrend');
    if (trendElement) {
        if (dashboard.security_score >= 80) {
            trendElement.textContent = '✅ Excellent';
            trendElement.className = 'metric-trend excellent';
        } else if (dashboard.security_score >= 60) {
            trendElement.textContent = '👍 Good';
            trendElement.className = 'metric-trend good';
        } else if (dashboard.security_score >= 40) {
            trendElement.textContent = '⚠️ Fair';
            trendElement.className = 'metric-trend warning';
        } else {
            trendElement.textContent = '❌ Poor';
            trendElement.className = 'metric-trend critical';
        }
    }
    
    // Update recent activity
    const activityList = document.getElementById('recentActivityList');
    if (activityList && dashboard.recent_events) {
        if (dashboard.recent_events.length > 0) {
            activityList.innerHTML = dashboard.recent_events.map(event => `
                <div class="activity-item ${event.severity.toLowerCase()}">
                    <div class="activity-icon">${getEventIcon(event.type)}</div>
                    <div class="activity-details">
                        <div class="activity-description">${escapeHtml(event.description)}</div>
                        <div class="activity-timestamp">${formatTimestamp(event.timestamp)}</div>
                    </div>
                </div>
            `).join('');
        } else {
            activityList.innerHTML = '<div class="no-activity">No recent security events</div>';
        }
    }
}

function getEventIcon(eventType) {
    const icons = {
        'LOGIN_SUCCESS': '🔐',
        'LOGIN_FAILED': '❌',
        'PASSWORD_ADDED': '💾',
        'PASSWORD_ACCESSED': '👁️',
        'PASSWORD_UPDATED': '✏️',
        'PASSWORD_DELETED': '🗑️',
        'SECURITY_AUDIT': '🔍',
        'ACCOUNT_LOCKED': '🔒',
        'SETTINGS_UPDATED': '⚙️',
        'VAULT_EXPORTED': '📤',
        'DEVICE_TRUSTED': '📱'
    };
    return icons[eventType] || '📝';
}

// ===== ENHANCED FEATURES =====
async function runSecurityAudit() {
    const masterPassword = await getMasterPassword();
    if (!masterPassword) return;
    
    try {
        showNotification('Running comprehensive security audit...', 'info');
        
        const response = await fetch('/api/vault/security-audit', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ master_password: masterPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayAuditResults(data.audit_results);
            showNotification('Security audit completed successfully', 'success');
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Audit error:', error);
        showNotification('Network error during audit', 'error');
    }
}

function displayAuditResults(results) {
    // Create audit results modal
    const modal = document.createElement('div');
    modal.className = 'audit-results-modal';
    modal.innerHTML = `
        <div class="audit-card">
            <div class="audit-header">
                <h2>🔍 Security Audit Results</h2>
                <button class="close-audit" onclick="this.closest('.audit-results-modal').remove()">×</button>
            </div>
            <div class="audit-content">
                <div class="audit-overview">
                    <h3>Audit Overview</h3>
                    <div class="audit-stats">
                        <div class="audit-stat">
                            <span class="stat-number">${results.total_passwords}</span>
                            <span class="stat-label">Total Passwords</span>
                        </div>
                        <div class="audit-stat ${results.compromised_count > 0 ? 'critical' : 'good'}">
                            <span class="stat-number">${results.compromised_count}</span>
                            <span class="stat-label">Compromised</span>
                        </div>
                        <div class="audit-stat ${results.weak_count > 0 ? 'warning' : 'good'}">
                            <span class="stat-number">${results.weak_count}</span>
                            <span class="stat-label">Weak</span>
                        </div>
                        <div class="audit-stat ${results.duplicate_count > 0 ? 'warning' : 'good'}">
                            <span class="stat-number">${results.duplicate_count}</span>
                            <span class="stat-label">Duplicates</span>
                        </div>
                        <div class="audit-stat ${results.old_count > 0 ? 'warning' : 'good'}">
                            <span class="stat-number">${results.old_count}</span>
                            <span class="stat-label">Old (90+ days)</span>
                        </div>
                    </div>
                </div>
                
                ${results.compromised_count > 0 ? `
                <div class="audit-section critical">
                    <h4>🚨 Compromised Passwords (Immediate Action Required)</h4>
                    <div class="compromised-list">
                        ${results.compromised_sites.map(site => `
                            <div class="compromised-item">
                                <span class="site-name">${escapeHtml(site.site)}</span>
                                <span class="username">${escapeHtml(site.username)}</span>
                                <span class="breach-count">${site.breach_count.toLocaleString()} breaches</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}
                
                ${results.weak_count > 0 ? `
                <div class="audit-section warning">
                    <h4>⚠️ Weak Passwords</h4>
                    <div class="weak-list">
                        ${results.weak_sites.map(site => `
                            <div class="weak-item">
                                <span class="site-name">${escapeHtml(site.site)}</span>
                                <span class="username">${escapeHtml(site.username)}</span>
                                <span class="strength-score">${site.strength_score}% strength</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}
                
                <div class="audit-actions">
                    <button onclick="this.closest('.audit-results-modal').remove()" class="audit-action-btn">Close Report</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

async function exportVaultData() {
    const masterPassword = await getMasterPassword();
    if (!masterPassword) return;
    
    try {
        showNotification('Preparing secure vault export...', 'info');
        
        const response = await fetch('/api/vault/export', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ master_password: masterPassword, format: 'json' })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Create and download file
            const blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vaultguard-backup-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            showNotification(`Exported ${data.exported_count} passwords successfully`, 'success');
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Export error:', error);
        showNotification('Network error during export', 'error');
    }
}

// ===== MANAGE DEVICES FEATURE =====
document.getElementById('manageDevices')?.addEventListener('click', openManageDevicesModal);

async function openManageDevicesModal() {
    try {
        const response = await fetch('/api/devices');
        const data = await response.json();

        if (!data.success) {
            showNotification('⚠️ Failed to load device list', 'error');
            return;
        }

        // Build modal dynamically
        const modal = document.createElement('div');
        modal.className = 'manage-devices-modal';
        modal.innerHTML = `
            <div class="modal-card">
                <div class="modal-header">
                    <h2>📱 Manage Trusted Devices</h2>
                    <button class="close-modal" onclick="this.closest('.manage-devices-modal').remove()">×</button>
                </div>
                <div class="modal-content">
                    ${
                        data.devices.length > 0
                        ? data.devices.map(d => `
                            <div class="device-item ${d.is_current ? 'current' : ''}">
                                <div class="device-info">
                                    <strong>${d.device_name}</strong>
                                    <small>IP: ${d.ip_address}</small><br>
                                    <small>Last seen: ${d.last_seen}</small>
                                </div>
                                ${
                                    d.is_trusted
                                    ? `<span class="trusted-badge">✅ Trusted</span>`
                                    : `<button class="trust-btn" data-id="${d.id}">Trust</button>`
                                }
                            </div>
                        `).join('')
                        : `<p style="text-align:center; color:var(--text-secondary);">No device records found.</p>`
                    }
                </div>
            </div>
        `;
        modal.style.cssText = `
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 10000;
        `;
        document.body.appendChild(modal);

        // Handle trust button click
        modal.querySelectorAll('.trust-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const deviceId = btn.dataset.id;
                const trustRes = await fetch(`/api/devices/${deviceId}/trust`, { method: 'POST' });
                const trustData = await trustRes.json();

                if (trustData.success) {
                    showNotification('✅ Device marked as trusted', 'success');
                    modal.remove();
                    openManageDevicesModal(); // Reload list
                } else {
                    showNotification(trustData.message || '⚠️ Could not trust device', 'error');
                }
            });
        });

    } catch (err) {
        console.error(err);
        showNotification('❌ Error loading devices', 'error');
    }
}



// ===== ENHANCED HELPER FUNCTIONS =====
function formatTimestamp(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffHours < 1) {
        return 'Just now';
    } else if (diffHours < 24) {
        return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    } else if (diffDays < 7) {
        return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    } else {
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    }
}

function showButtonLoading(buttonId, loadingText) {
    const button = document.getElementById(buttonId);
    if (button) {
        button.disabled = true;
        button.textContent = loadingText;
        button.style.opacity = '0.7';
    }
}

function hideButtonLoading(buttonId, originalText) {
    const button = document.getElementById(buttonId);
    if (button) {
        button.disabled = false;
        button.textContent = originalText;
        button.style.opacity = '1';
    }
}

function showLoadingState(component) {
    const loadingElement = document.getElementById(`${component}-loading`);
    if (loadingElement) {
        loadingElement.style.display = 'block';
    }
}

function hideLoadingState(component) {
    const loadingElement = document.getElementById(`${component}-loading`);
    if (loadingElement) {
        loadingElement.style.display = 'none';
    }
}

// ===== PASSWORD GENERATOR FUNCTIONS =====
function updateLengthDisplay(length) {
    if (!elements.lengthValueDisplay) return;
    
    passwordGeneratorSettings.length = length;
    
    // Update color and label based on length
    let color = '#ff4757';
    let label = '(Weak)';
    
    if (length >= 32) {
        color = '#2ed573';
        label = '(Fortress)';
    } else if (length >= 20) {
        color = '#58a6ff';
        label = '(Military)';
    } else if (length >= 16) {
        color = '#ffa502';
        label = '(Strong)';
    } else if (length >= 12) {
        color = '#ff6348';
        label = '(Good)';
    }
    
    elements.lengthValueDisplay.style.color = color;
    elements.lengthValueDisplay.textContent = `${length} ${label}`;
}

function generateNewPassword() {
    if (!elements.generateBtn) return;
    
    elements.generateBtn.textContent = 'Generating Secure Password...';
    elements.generateBtn.disabled = true;
    
    setTimeout(() => {
        const password = generateRandomPassword();
        if (elements.generatedPassword) {
            elements.generatedPassword.value = password;
            elements.generatedPassword.style.animation = 'fadeIn 0.3s ease-out';
        }
        
        elements.generateBtn.textContent = '🎲 Generate Secure Password';
        elements.generateBtn.disabled = false;
        showNotification('Cryptographically secure password generated!', 'success');
    }, 500);
}

async function copyGeneratedPassword() {
    if (!elements.generatedPassword?.value) {
        showNotification('No generated password to copy', 'warning');
        return;
    }
    
    try {
        await navigator.clipboard.writeText(elements.generatedPassword.value);
        showNotification('Generated password copied securely!', 'success');
        
        // Security: Clear clipboard after 30 seconds
        setTimeout(() => {
            navigator.clipboard.writeText('').catch(() => {});
        }, 30000);
    } catch (err) {
        console.error('Clipboard error:', err);
        showNotification('Failed to copy password', 'error');
    }
}

function useGeneratedPassword() {
    if (!elements.generatedPassword?.value || !elements.passwordInput) {
        showNotification('No generated password to use', 'warning');
        return;
    }
    
    elements.passwordInput.value = elements.generatedPassword.value;
    analyzePassword(elements.generatedPassword.value);
    showNotification('Password moved to analyzer!', 'success');
    
    // Scroll to analyzer if it exists
    const analyzerSection = document.querySelector('.password-analyzer');
    if (analyzerSection) {
        analyzerSection.scrollIntoView({ behavior: 'smooth' });
    }
}

function updatePasswordGeneratorSettings() {
    if (elements.lengthSlider) {
        passwordGeneratorSettings.length = parseInt(elements.lengthSlider.value);
    }
    if (elements.includeUpper) {
        passwordGeneratorSettings.includeUpper = elements.includeUpper.checked;
    }
    if (elements.includeLower) {
        passwordGeneratorSettings.includeLower = elements.includeLower.checked;
    }
    if (elements.includeNumbers) {
        passwordGeneratorSettings.includeNumbers = elements.includeNumbers.checked;
    }
    if (elements.includeSymbols) {
        passwordGeneratorSettings.includeSymbols = elements.includeSymbols.checked;
    }
}

function validateGeneratorSettings() {
    const hasAnySelected = [
        elements.includeUpper?.checked,
        elements.includeLower?.checked,
        elements.includeNumbers?.checked,
        elements.includeSymbols?.checked
    ].some(Boolean);
    
    if (!hasAnySelected) {
        showNotification('At least one character type must be selected', 'warning');
        // Auto-select lowercase as fallback
        if (elements.includeLower) {
            elements.includeLower.checked = true;
            passwordGeneratorSettings.includeLower = true;
        }
    }
}

function generateRandomPassword(customLength = null) {
    updatePasswordGeneratorSettings();
    
    const length = customLength || passwordGeneratorSettings.length;
    let charset = '';
    
    // Build character set based on settings
    if (passwordGeneratorSettings.includeUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (passwordGeneratorSettings.includeLower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (passwordGeneratorSettings.includeNumbers) charset += '0123456789';
    if (passwordGeneratorSettings.includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?~`';
    
    // Fallback to full charset if nothing selected
    if (!charset) {
        charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        showNotification('No character types selected, using all types', 'warning');
    }
    
    let password = '';
    
    // Ensure at least one character from each selected type
    const requiredChars = [];
    if (passwordGeneratorSettings.includeUpper) requiredChars.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (passwordGeneratorSettings.includeLower) requiredChars.push('abcdefghijklmnopqrstuvwxyz');
    if (passwordGeneratorSettings.includeNumbers) requiredChars.push('0123456789');
    if (passwordGeneratorSettings.includeSymbols) requiredChars.push('!@#$%^&*()_+-=[]{}|;:,.<>?~`');
    
    // Add one character from each required type
    requiredChars.forEach(charSet => {
        const randomIndex = Math.floor(Math.random() * charSet.length);
        password += charSet[randomIndex];
    });
    
    // Fill remaining length with random characters
    const remainingLength = Math.max(0, length - requiredChars.length);
    const array = new Uint8Array(remainingLength);
    crypto.getRandomValues(array);
    
    for (let i = 0; i < remainingLength; i++) {
        password += charset.charAt(array[i] % charset.length);
    }
    
    // Shuffle the password to avoid predictable patterns
    return shuffleString(password);
}

function shuffleString(str) {
    const array = str.split('');
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array.join('');
}

function initializePasswordGenerator() {
    // Auto-generate initial password if on generator page
    if (elements.generateBtn && elements.generatedPassword) {
        setTimeout(() => {
            generateNewPassword();
        }, 500);
    }
    
    // Set initial slider value display
    if (elements.lengthSlider && elements.lengthValueDisplay) {
        updateLengthDisplay(parseInt(elements.lengthSlider.value));
    }
}

// ===== PASSWORD MODAL FUNCTIONS =====
function displayPasswordModal(item, password) {
    // Remove any existing modals
    const existingModals = document.querySelectorAll('.password-modal');
    existingModals.forEach(modal => modal.remove());
    
    const modal = document.createElement('div');
    modal.className = 'password-modal';
    modal.innerHTML = `
        <div class="password-modal-content">
            <div class="modal-header">
                <h3>🔓 Securely Decrypted Password</h3>
                <button onclick="this.closest('.password-modal').remove()" class="close-modal-btn">×</button>
            </div>
            <div class="password-display">
                <div class="password-field">
                    <label>Site/Service:</label>
                    <span class="field-value">${escapeHtml(item.site)}</span>
                </div>
                <div class="password-field">
                    <label>Category:</label>
                    <span class="field-value">${escapeHtml(item.category || 'General')}</span>
                </div>
                <div class="password-field">
                    <label>Username:</label>
                    <span class="field-value">${escapeHtml(item.username)}</span>
                </div>
                <div class="password-field">
                    <label>Password:</label>
                    <div class="password-reveal-container">
                        <span class="revealed-password" id="revealed-password-${item.id}">${escapeHtml(password)}</span>
                        <button class="reveal-toggle" onclick="togglePasswordVisibilityInModal('revealed-password-${item.id}')">👁️</button>
                    </div>
                </div>
                ${item.notes ? `
                <div class="password-field">
                    <label>Notes:</label>
                    <span class="field-value">${escapeHtml(item.notes)}</span>
                </div>
                ` : ''}
                <div class="password-stats">
                    <div class="stat">Created: ${formatTimestamp(item.created_at)}</div>
                    <div class="stat">Updated: ${formatTimestamp(item.updated_at)}</div>
                    <div class="stat">Strength: ${item.strength_score || 0}%</div>
                    ${item.access_count ? `<div class="stat">Accessed: ${item.access_count} times</div>` : ''}
                    ${item.last_accessed ? `<div class="stat">Last accessed: ${formatTimestamp(item.last_accessed)}</div>` : ''}
                </div>
                <div class="security-timer">
                    🔒 Auto-hide in <span id="timer-${item.id}">15</span> seconds for security
                </div>
            </div>
            <div class="modal-actions">
                <button onclick="copyPasswordFromModal('${password.replace(/'/g, "\\'")}');" class="copy-modal-btn">📋 Secure Copy</button>
                <button onclick="analyzePasswordFromModal('${password.replace(/'/g, "\\'")}');" class="analyze-modal-btn">🔍 Analyze Security</button>
                <button onclick="this.closest('.password-modal').remove()" class="close-modal-btn secondary">Close</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Auto-hide countdown
    startSecurityTimer(item.id, modal);
    
    // Add click outside to close
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

function startSecurityTimer(itemId, modal) {
    let timeLeft = 15;
    const timerElement = modal.querySelector(`#timer-${itemId}`);
    
    const countdown = setInterval(() => {
        timeLeft--;
        if (timerElement) {
            timerElement.textContent = timeLeft;
            
            // Change color as time runs out
            if (timeLeft <= 5) {
                timerElement.style.color = '#ff4757';
                timerElement.style.fontWeight = 'bold';
            }
        }
        
        if (timeLeft <= 0) {
            clearInterval(countdown);
            if (modal.parentNode) {
                modal.style.animation = 'modalFadeOut 0.3s ease-out';
                setTimeout(() => modal.remove(), 300);
            }
        }
    }, 1000);
}

function togglePasswordVisibilityInModal(passwordElementId) {
    const passwordElement = document.getElementById(passwordElementId);
    const toggleButton = passwordElement?.nextElementSibling;
    
    if (passwordElement) {
        if (passwordElement.style.filter === 'blur(5px)') {
            passwordElement.style.filter = '';
            if (toggleButton) toggleButton.textContent = '🙈';
        } else {
            passwordElement.style.filter = 'blur(5px)';
            if (toggleButton) toggleButton.textContent = '👁️';
        }
    }
}

async function copyPasswordFromModal(password) {
    try {
        await navigator.clipboard.writeText(password);
        showNotification('Password securely copied!', 'success');
        
        // Security: Clear clipboard after 30 seconds
        setTimeout(() => {
            navigator.clipboard.writeText('').catch(() => {});
        }, 30000);
    } catch (error) {
        console.error('Failed to copy password:', error);
        showNotification('Failed to copy password', 'error');
    }
}

function analyzePasswordFromModal(password) {
    // Close modal
    const modal = document.querySelector('.password-modal');
    if (modal) modal.remove();
    
    // Set password in analyzer and analyze
    if (elements.passwordInput) {
        elements.passwordInput.value = password;
        analyzePassword(password);
        
        // Scroll to analyzer
        const analyzerSection = document.querySelector('.password-analyzer');
        if (analyzerSection) {
            analyzerSection.scrollIntoView({ behavior: 'smooth' });
        }
        
        showNotification('Password moved to security analyzer!', 'success');
    }
}

// ===== UTILITY FUNCTIONS =====
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ===== SECURITY FUNCTIONS =====
function checkSecureContext() {
    if (!window.isSecureContext) {
        showNotification('Warning: Not running in secure context. Some features may be limited.', 'warning');
        return false;
    }
    return true;
}

function handleVisibilityChange() {
    if (document.hidden && masterPasswordCache) {
        // Clear master password cache when tab becomes hidden
        setTimeout(() => {
            if (document.hidden) { // Double-check it's still hidden
                masterPasswordCache = null;
                showNotification('Master password cleared for security', 'info');
            }
        }, 30000);
    }
}

function handleKeyboardShortcuts(event) {
    // Ctrl+G: Generate password
    if (event.ctrlKey && event.key === 'g') {
        event.preventDefault();
        if (elements.passwordInput) {
            generateAndAnalyzePassword();
        } else if (elements.generateBtn) {
            generateNewPassword();
        }
    }
    
    // Ctrl+C: Copy password (when focused on password input)
    if (event.ctrlKey && event.key === 'c' && document.activeElement === elements.passwordInput) {
        event.preventDefault();
        copyPasswordToClipboard();
    }
    
    // Escape: Close modals
    if (event.key === 'Escape') {
        if (elements.authModal?.classList.contains('show')) {
            closeAuthModal();
        }
        
        if (elements.securityDashboard?.style.display === 'block') {
            elements.securityDashboard.style.display = 'none';
        }
        
        if (elements.notificationSettingsModal?.style.display === 'block') {
            elements.notificationSettingsModal.style.display = 'none';
        }
        
        const passwordModal = document.querySelector('.password-modal');
        if (passwordModal) {
            passwordModal.remove();
        }
        
        const auditModal = document.querySelector('.audit-results-modal');
        if (auditModal) {
            auditModal.remove();
        }
    }
    
    // Ctrl+L: Focus on login
    if (event.ctrlKey && event.key === 'l') {
        event.preventDefault();
        if (elements.loginBtn) {
            openAuthModal();
        }
    }
    
    // Ctrl+D: Open dashboard (if logged in)
    if (event.ctrlKey && event.key === 'd') {
        event.preventDefault();
        if (elements.securityDashboardBtn) {
            toggleSecurityDashboard();
        }
    }
    
    // Ctrl+S: Save password (if in vault)
    if (event.ctrlKey && event.key === 's') {
        event.preventDefault();
        if (elements.savePasswordBtn && !elements.savePasswordBtn.disabled) {
            savePassword();
        }
    }
}

function recordPerformanceMetric(metric, value) {
    performanceMetrics[metric] = value;
    
    // Log performance issues
    if (metric === 'analysisTime' && value > 1000) {
        console.warn('Password analysis taking longer than expected:', value + 'ms');
    }
    
    if (metric === 'apiCallCount' && value > 100) {
        console.warn('High API call count detected:', value);
    }
}

function showSecurityStatus() {
    setTimeout(() => {
        if (location.protocol === 'https:') {
            showNotification('Secure HTTPS connection established with enhanced features', 'success');
        } else {
            showNotification('Warning: Use HTTPS for maximum security and all features', 'warning');
        }
    }, 1000);
}

// ===== ENHANCED NOTIFICATION SYSTEM =====
function showNotification(message, type = 'success') {
    // Remove existing notifications of the same type
    const existingNotifications = document.querySelectorAll(`.notification.${type}`);
    existingNotifications.forEach(notification => {
        notification.style.animation = 'slideOutRight 0.3s ease-in';
        setTimeout(() => notification.remove(), 300);
    });
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    const colors = {
        success: 'linear-gradient(135deg, #2ed573, #17d97a)',
        error: 'linear-gradient(135deg, #ff4757, #ff3742)',
        info: 'linear-gradient(135deg, #3742fa, #2f3542)',
        warning: 'linear-gradient(135deg, #ffa502, #ff6348)'
    };
    
    const icons = {
        success: '✅',
        error: '❌',
        info: 'ℹ️',
        warning: '⚠️'
    };
    
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${colors[type] || colors.success};
        color: white;
        padding: 16px 24px;
        border-radius: 12px;
        z-index: 10000;
        font-weight: 600;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        max-width: 400px;
        word-wrap: break-word;
        animation: slideInRight 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        backdrop-filter: blur(15px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        cursor: pointer;
        transition: transform 0.2s ease;
    `;
    
    notification.innerHTML = `<span style="margin-right: 8px;">${icons[type] || icons.success}</span>${message}`;
    
    // Click to dismiss
    notification.addEventListener('click', () => {
        notification.style.animation = 'slideOutRight 0.3s ease-in';
        setTimeout(() => notification.remove(), 300);
    });
    
    // Hover effect
    notification.addEventListener('mouseenter', () => {
        notification.style.transform = 'translateY(-2px) scale(1.02)';
    });
    
    notification.addEventListener('mouseleave', () => {
        notification.style.transform = 'translateY(0) scale(1)';
    });
    
    document.body.appendChild(notification);
    
    // Auto-hide based on type
    const autoHideTime = type === 'error' ? 6000 : 4000;
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOutRight 0.3s ease-in';
            setTimeout(() => notification.remove(), 300);
        }
    }, autoHideTime);
}


// ===== TEST NOTIFICATION FEATURE =====
async function sendTestNotification() {
    try {
        showNotification('🔔 Sending test notification...', 'info');

        const response = await fetch('/api/notify/test', {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (data.success) {
            showNotification('✅ Test notification sent successfully! Check your email or SMS.', 'success');
        } else {
            showNotification(data.message || '⚠️ Notification could not be sent.', 'error');
        }
    } catch (error) {
        console.error('Notification test failed:', error);
        showNotification('❌ Server error while sending test notification', 'error');
    }
}

document.addEventListener("DOMContentLoaded", async () => {

    // 1 – Check if backend requires 2FA
    try {
        const res = await fetch("/api/me");
        const data = await res.json();

        if (data.force_2fa === true) {
            show2FAModal();
            return; 
        }
        
        // 🔥 FIX: Only load AI stats if authenticated
        if (data.authenticated) {
            loadAIThreatStats();
        }
        
    } catch (e) {
        console.error("2FA check failed", e);
    }

    // 2 – Attach notification test button ONLY if logged in
    if (document.body.classList.contains('logged-in')) {
        const testNotificationBtn = document.getElementById('testNotifications');
        if (testNotificationBtn) {
            testNotificationBtn.addEventListener('click', sendTestNotification);
        }
    }

    // 3 – Load dashboard normally (but don't call AI stats here - we do it above)
    if (typeof loadSecurityDashboard === 'function') {
        loadSecurityDashboard();
    }
});


// ===== ENHANCED CSS STYLES =====
function addEnhancedStyles() {
    const style = document.createElement('style');
    style.textContent = `
        /* Enhanced Animations */
        @keyframes strengthPulse {
            0%, 100% { 
                box-shadow: 0 0 15px rgba(46, 213, 115, 0.6);
                transform: scale(1);
            }
            50% { 
                box-shadow: 0 0 25px rgba(46, 213, 115, 0.9);
                transform: scale(1.02);
            }
        }
        
        @keyframes breachPulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(1.05); }
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes modalFadeIn {
            from { opacity: 0; transform: scale(0.85) translateY(-20px); }
            to { opacity: 1; transform: scale(1) translateY(0); }
        }
        
        @keyframes modalFadeOut {
            from { opacity: 1; transform: scale(1) translateY(0); }
            to { opacity: 0; transform: scale(0.85) translateY(-20px); }
        }
        
        @keyframes slideInRight {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes slideOutRight {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
        
        /* Enhanced Security Score Badge */
        .security-score-badge {
            background: linear-gradient(135deg, #3742fa, #5352ed);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: 700;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.25rem;
            transition: all 0.3s ease;
        }
        
        .security-score-badge::before {
            content: '🛡️';
            font-size: 1rem;
        }
        
        .security-score-badge.excellent {
            background: linear-gradient(135deg, #2ed573, #17d97a);
        }
        
        .security-score-badge.good {
            background: linear-gradient(135deg, #58a6ff, #4f94d4);
        }
        
        .security-score-badge.fair {
            background: linear-gradient(135deg, #ffa502, #ff6348);
        }
        
        .security-score-badge.poor {
            background: linear-gradient(135deg, #ff4757, #ff3742);
        }
        
        /* Enhanced Header Buttons */
        .header-btn {
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            color: var(--text-primary);
            padding: 0.6rem;
            border-radius: 10px;
            cursor: pointer;
            font-size: 1.1rem;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
        }
        
        .header-btn:hover {
            background: var(--glass-border);
            transform: translateY(-1px);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        
        /* Enhanced Dashboard Styles */
        .security-dashboard-card {
            position: fixed;
            top: 80px;
            right: 20px;
            width: 400px;
            max-height: 80vh;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            box-shadow: var(--shadow-elevated);
            z-index: 1000;
            overflow-y: auto;
            animation: modalFadeIn 0.3s ease-out;
        }
        
        .dashboard-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        .close-dashboard {
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: var(--text-secondary);
            padding: 0.5rem;
            border-radius: 8px;
            transition: all 0.2s ease;
        }
        
        .close-dashboard:hover {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-primary);
        }
        
        .security-metrics {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            padding: 1.5rem;
        }
        
        .metric-card {
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            border-radius: 12px;
            padding: 1rem;
            text-align: center;
        }
        
        .metric-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent-blue);
            margin-bottom: 0.5rem;
        }
        
        .metric-label {
            font-size: 0.8rem;
            color: var(--text-secondary);
            font-weight: 600;
        }
        
        .metric-trend {
            font-size: 0.7rem;
            margin-top: 0.25rem;
            padding: 0.25rem 0.5rem;
            border-radius: 12px;
            font-weight: 600;
        }
        
        .metric-trend.excellent {
            background: rgba(46, 213, 115, 0.2);
            color: #2ed573;
        }
        
        .metric-trend.good {
            background: rgba(88, 166, 255, 0.2);
            color: #58a6ff;
        }
        
        .metric-trend.warning {
            background: rgba(255, 165, 2, 0.2);
            color: #ffa502;
        }
        
        .metric-trend.critical {
            background: rgba(255, 71, 87, 0.2);
            color: #ff4757;
        }
        
        /* Enhanced Vault Item Styles */
        .vault-item.compromised {
            border-left: 4px solid #ff4757;
            background: rgba(255, 71, 87, 0.05);
        }
        
        .category-badge {
            background: var(--accent-blue);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: 600;
        }
        
        .strength-indicator {
            padding: 0.25rem 0.5rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .strength-indicator.excellent {
            background: rgba(46, 213, 115, 0.2);
            color: #2ed573;
        }
        
        .strength-indicator.good {
            background: rgba(88, 166, 255, 0.2);
            color: #58a6ff;
        }
        
        .strength-indicator.fair {
            background: rgba(255, 165, 2, 0.2);
            color: #ffa502;
        }
        
        .strength-indicator.poor {
            background: rgba(255, 71, 87, 0.2);
            color: #ff4757;
        }
        
        .compromised-indicator {
            background: rgba(255, 71, 87, 0.2);
            color: #ff4757;
            padding: 0.25rem 0.5rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            animation: breachPulse 2s ease-in-out infinite;
        }
        
        .security-indicators {
            display: flex;
            gap: 0.5rem;
            margin: 0.5rem 0;
            flex-wrap: wrap;
        }
        
        .password-notes {
            background: rgba(88, 166, 255, 0.1);
            border: 1px solid rgba(88, 166, 255, 0.3);
            padding: 0.5rem;
            border-radius: 8px;
            margin: 0.5rem 0;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }
        
        .access-info {
            display: flex;
            justify-content: space-between;
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 0.5rem;
        }
        
        /* Responsive Design Improvements */
        @media (max-width: 768px) {
            .security-dashboard-card {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                width: 100%;
                max-height: 100vh;
                border-radius: 0;
            }
            
            .security-metrics {
                grid-template-columns: 1fr;
            }
        }
    `;
    document.head.appendChild(style);
}

// ===== CONSOLE SECURITY WARNING =====
function showSecurityWarning() {
    console.log('%c🛡️ VaultGuard Enhanced Security Notice', 'color: #2ed573; font-size: 16px; font-weight: bold;');
    console.log('%cThis enhanced application handles sensitive password data with military-grade security.', 'color: #ffa502; font-size: 12px;');
    console.log('%cFeatures: HTTPS, AES-256, Real-time breach detection, Smart notifications, Security dashboard', 'color: #58a6ff; font-size: 12px;');
    console.log('%cDo not paste or execute unknown code in this console.', 'color: #ff4757; font-size: 12px;');
    console.log('%cAll passwords are encrypted with AES-256 and monitored for breaches.', 'color: #58a6ff; font-size: 12px;');
}

// ===== ERROR HANDLING =====
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    showNotification('An unexpected error occurred', 'error');
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    showNotification('Network or server error occurred', 'error');
    event.preventDefault();
});

// ===== SECURITY CLEANUP ON PAGE UNLOAD =====
window.addEventListener('beforeunload', () => {
    // Clear sensitive data
    masterPasswordCache = null;
    
    // Clear any password displays
    const passwordDisplays = document.querySelectorAll('.revealed-password');
    passwordDisplays.forEach(el => {
        el.textContent = '••••••••••';
    });
    
    // Clear clipboard (best effort)
    if (navigator.clipboard) {
        navigator.clipboard.writeText('').catch(() => {});
    }
    
    // Clear form data
    if (elements.passwordInput) elements.passwordInput.value = '';
    if (elements.generatedPassword) elements.generatedPassword.value = '';
    if (elements.vaultPassword) elements.vaultPassword.value = '';
});

// ===== GLOBAL FUNCTION EXPORTS =====
// Make functions available globally for onclick handlers
window.copyVaultPassword = copyVaultPassword;
window.viewVaultPassword = viewVaultPassword;
window.editVaultPassword = editVaultPassword;
window.deleteVaultPassword = deleteVaultPassword;
window.clearVaultFilter = clearVaultFilter;
window.togglePasswordVisibilityInModal = togglePasswordVisibilityInModal;
window.copyPasswordFromModal = copyPasswordFromModal;
window.analyzePasswordFromModal = analyzePasswordFromModal;

// Export main object for global access if needed
window.VaultGuardEnhanced = {
    // Core functions
    analyzePassword,
    generateRandomPassword,
    openAuthModal,
    closeAuthModal,
    showNotification,
    initialize,
    
    // Enhanced features
    loadSecurityDashboard,
    runSecurityAudit,
    exportVaultData,
    loadVaultData,
    
    // Utilities
    formatTimestamp,
    escapeHtml,
    debounce,
    throttle,
    
    // State
    getSecurityScore: () => securityScore,
    getVaultData: () => vaultData,
    getDashboardData: () => dashboardData,
    getPerformanceMetrics: () => performanceMetrics
};

// ===== MAIN INITIALIZATION =====
// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}

// Show security warning in console
showSecurityWarning();

// ===== ENHANCED FEATURES INITIALIZATION =====
// Additional initialization for enhanced features
document.addEventListener('DOMContentLoaded', () => {
    // Initialize notification settings if logged in
    if (document.body.classList.contains('logged-in')) {
        // Auto-load security score
        setTimeout(() => {
            if (elements.securityScoreValue && securityScore > 0) {
                elements.securityScoreValue.textContent = securityScore;
            }
        }, 1000);
        
        // Check for security warnings
        setTimeout(() => {
            if (dashboardData) {
                if (dashboardData.compromised_passwords > 0) {
                    showNotification(`⚠️ You have ${dashboardData.compromised_passwords} compromised passwords! Check your security dashboard.`, 'warning');
                }
                
                if (dashboardData.password_age_warning) {
                    showNotification('Your master password is over 90 days old. Consider updating it for better security.', 'warning');
                }
            }
        }, 3000);
    }
    
    // Enhanced search functionality
    const searchInput = document.getElementById('vault-search');
    const clearBtn = document.getElementById('clearSearch');
    
    if (searchInput && clearBtn) {
        // Enhanced search with categories and notes
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            
            if (searchTerm.length > 0) {
                clearBtn.style.display = 'block';
                
                // Highlight matching results
                const vaultItems = document.querySelectorAll('.vault-item');
                vaultItems.forEach(item => {
                    const siteName = item.querySelector('.site-name')?.textContent.toLowerCase() || '';
                    const username = item.querySelector('.username-display')?.textContent.toLowerCase() || '';
                    const category = item.querySelector('.category-badge')?.textContent.toLowerCase() || '';
                    const notes = item.querySelector('.password-notes')?.textContent.toLowerCase() || '';
                    
                    const matches = siteName.includes(searchTerm) || 
                                  username.includes(searchTerm) || 
                                  category.includes(searchTerm) || 
                                  notes.includes(searchTerm);
                    
                    if (matches) {
                        item.style.display = 'block';
                        item.style.border = '2px solid var(--accent-blue)';
                        item.style.background = 'rgba(88, 166, 255, 0.05)';
                    } else {
                        item.style.display = 'none';
                    }
                });
            } else {
                clearBtn.style.display = 'none';
                
                // Reset all items
                const vaultItems = document.querySelectorAll('.vault-item');
                vaultItems.forEach(item => {
                    item.style.display = 'block';
                    item.style.border = '';
                    item.style.background = '';
                });
            }
        });
        
        clearBtn.addEventListener('click', () => {
            searchInput.value = '';
            clearBtn.style.display = 'none';
            
            // Reset all items
            const vaultItems = document.querySelectorAll('.vault-item');
            vaultItems.forEach(item => {
                item.style.display = 'block';
                item.style.border = '';
                item.style.background = '';
            });
            
            searchInput.focus();
        });
    }
    
    // Enhanced keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Ctrl+Shift+A: Run security audit
        if (e.ctrlKey && e.shiftKey && e.key === 'A') {
            e.preventDefault();
            if (elements.auditVault) {
                runSecurityAudit();
            }
        }
        
        // Ctrl+Shift+E: Export vault
        if (e.ctrlKey && e.shiftKey && e.key === 'E') {
            e.preventDefault();
            if (elements.exportVault) {
                exportVaultData();
            }
        }
        
        // Ctrl+Shift+N: Open notification settings
        if (e.ctrlKey && e.shiftKey && e.key === 'N') {
            e.preventDefault();
            if (elements.notificationSettingsBtn) {
                elements.notificationSettingsBtn.click();
            }
        }
        
        // F1: Show help/shortcuts
        if (e.key === 'F1') {
            e.preventDefault();
            showKeyboardShortcuts();
        }
    });
    
    // Auto-save form data to prevent loss
    const formInputs = [elements.siteName, elements.vaultUsername, elements.vaultPassword, elements.vaultNotes];
    formInputs.forEach(input => {
        if (input) {
            input.addEventListener('input', debounce(() => {
                const formData = {
                    site: elements.siteName?.value || '',
                    username: elements.vaultUsername?.value || '',
                    password: elements.vaultPassword?.value || '',
                    notes: elements.vaultNotes?.value || '',
                    category: elements.vaultCategory?.value || 'General'
                };
                
                // Only save if there's meaningful data
                if (formData.site || formData.username) {
                    sessionStorage.setItem('vaultguard_form_data', JSON.stringify(formData));
                }
            }, 1000));
        }
    });
    
    // Restore form data on page load
    try {
        const savedFormData = sessionStorage.getItem('vaultguard_form_data');
        if (savedFormData) {
            const formData = JSON.parse(savedFormData);
            
            if (elements.siteName) elements.siteName.value = formData.site || '';
            if (elements.vaultUsername) elements.vaultUsername.value = formData.username || '';
            if (elements.vaultNotes) elements.vaultNotes.value = formData.notes || '';
            if (elements.vaultCategory) elements.vaultCategory.value = formData.category || 'General';
            
            // Don't restore password for security
            if (formData.site || formData.username) {
                showNotification('Form data restored from previous session', 'info');
            }
        }
    } catch (error) {
        console.warn('Failed to restore form data:', error);
    }
    
    // Clear saved form data when password is saved successfully
    if (elements.savePasswordBtn) {
        const originalSavePassword = savePassword;
        savePassword = async function() {
            const result = await originalSavePassword.apply(this, arguments);
            if (result !== false) { // If save was successful
                sessionStorage.removeItem('vaultguard_form_data');
            }
            return result;
        };
    }
});

function showKeyboardShortcuts() {
    const shortcuts = [
        { key: 'Ctrl+G', action: 'Generate password' },
        { key: 'Ctrl+C', action: 'Copy password (when focused)' },
        { key: 'Ctrl+L', action: 'Open login modal' },
        { key: 'Ctrl+D', action: 'Toggle security dashboard' },
        { key: 'Ctrl+S', action: 'Save password to vault' },
        { key: 'Ctrl+Shift+A', action: 'Run security audit' },
        { key: 'Ctrl+Shift+E', action: 'Export vault data' },
        { key: 'Ctrl+Shift+N', action: 'Open notification settings' },
        { key: 'Escape', action: 'Close modals/dialogs' },
        { key: 'F1', action: 'Show this help' }
    ];
    
    const modal = document.createElement('div');
    modal.className = 'keyboard-shortcuts-modal';
    modal.innerHTML = `
        <div class="shortcuts-card">
            <div class="shortcuts-header">
                <h2>⌨️ Keyboard Shortcuts</h2>
                <button onclick="this.closest('.keyboard-shortcuts-modal').remove()" class="close-shortcuts">×</button>
            </div>
            <div class="shortcuts-content">
                ${shortcuts.map(shortcut => `
                    <div class="shortcut-item">
                        <kbd class="shortcut-key">${shortcut.key}</kbd>
                        <span class="shortcut-action">${shortcut.action}</span>
                    </div>
                `).join('')}
            </div>
            <div class="shortcuts-footer">
                <p>💡 Pro tip: Most shortcuts work globally, some require focus on specific elements</p>
            </div>
        </div>
    `;
    
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 10001;
        animation: modalFadeIn 0.3s ease-out;
    `;
    
    document.body.appendChild(modal);
    
    // Close on click outside
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
    
    // Auto-close after 10 seconds
    setTimeout(() => {
        if (modal.parentNode) {
            modal.remove();
        }
    }, 10000);
}

// ===== PERIODIC SECURITY CHECKS =====
// Run periodic security checks if logged in
if (document.body.classList.contains('logged-in')) {
    // Check for compromised passwords every 30 minutes
    setInterval(async () => {
        if (vaultData.length > 0 && currentUserSalt) {
            const compromisedCount = vaultData.filter(item => item.is_compromised).length;
            const weakCount = vaultData.filter(item => (item.strength_score || 0) < 50).length;
            
            if (compromisedCount > 0 || weakCount > 5) {
                showNotification(`Security Alert: ${compromisedCount} compromised and ${weakCount} weak passwords detected. Run a security audit!`, 'warning');
            }
        }
    }, 30 * 60 * 1000); // 30 minutes
    
    // Refresh security dashboard every 5 minutes
    setInterval(async () => {
        if (elements.securityDashboard?.style.display === 'block') {
            await loadSecurityDashboard();
        }
    }, 5 * 60 * 1000); // 5 minutes
}

// ===== PERFORMANCE MONITORING =====
// Monitor performance and show warnings
setInterval(() => {
    if (performanceMetrics.apiCallCount > 50) {
        console.warn('High API usage detected. Consider optimizing requests.');
        performanceMetrics.apiCallCount = 0; // Reset counter
    }
    
    // Check memory usage if available
    if (performance.memory) {
        const memoryUsage = performance.memory.usedJSHeapSize / 1024 / 1024; // MB
        if (memoryUsage > 100) {
            console.warn(`High memory usage: ${memoryUsage.toFixed(2)}MB`);
        }
    }
}, 60000); // Every minute

console.log('🎉 VaultGuard Enhanced fully loaded with all security features!');


// ===== AI GUARDIAN INTEGRATION (Enhanced) =====
async function loadAIThreatStats() {
    try {
        const response = await fetch('/api/ai/threat-stats?days=7');
        const data = await response.json();
        
        if (data.success) {
            displayAIStats(data.statistics, data.ai_model_status);
        }
    } catch (error) {
        console.error('AI Guardian unavailable:', error);
    }
}

// ===== REPLACE ENTIRE displayAIStats AND loadRecentThreatScores FUNCTIONS =====

function displayAIStats(stats, modelStatus) {
    // Remove any existing AI section first
    const existing = document.querySelector('.ai-guardian-section');
    if (existing) existing.remove();
    
    const aiStatsHTML = `
        <div class="ai-guardian-section" style="
            margin-top: 2rem;
            padding: 1.5rem;
            background: linear-gradient(135deg, rgba(88, 166, 255, 0.1), rgba(46, 213, 115, 0.1));
            border: 1px solid rgba(88, 166, 255, 0.3);
            border-radius: 12px;
        ">
            <h3 style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                <span style="font-size: 1.5rem;">🤖</span>
                <span>AI Guardian Threat Intelligence</span>
            </h3>
            
            <!-- Stats Grid -->
            <div style="
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 1rem;
                margin-bottom: 1rem;
            ">
                <div style="
                    background: var(--card-bg);
                    padding: 1rem;
                    border-radius: 8px;
                    text-align: center;
                    border: 1px solid var(--border-color);
                ">
                    <div style="font-size: 2rem; font-weight: 700; color: var(--accent-blue);">
                        ${stats.total_analyses}
                    </div>
                    <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem;">
                        Logins Analyzed
                    </div>
                </div>
                
                <div style="
                    background: var(--card-bg);
                    padding: 1rem;
                    border-radius: 8px;
                    text-align: center;
                    border: 1px solid rgba(46, 213, 115, 0.3);
                ">
                    <div style="font-size: 2rem; font-weight: 700; color: #2ed573;">
                        ${stats.safe_count}
                    </div>
                    <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem;">
                        ✅ Safe
                    </div>
                </div>
                
                <div style="
                    background: var(--card-bg);
                    padding: 1rem;
                    border-radius: 8px;
                    text-align: center;
                    border: 1px solid rgba(255, 165, 2, 0.3);
                ">
                    <div style="font-size: 2rem; font-weight: 700; color: #ffa502;">
                        ${stats.suspicious_count}
                    </div>
                    <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem;">
                        ⚠️ Suspicious
                    </div>
                </div>
                
                <div style="
                    background: var(--card-bg);
                    padding: 1rem;
                    border-radius: 8px;
                    text-align: center;
                    border: 1px solid rgba(255, 71, 87, 0.3);
                ">
                    <div style="font-size: 2rem; font-weight: 700; color: #ff4757;">
                        ${stats.critical_count}
                    </div>
                    <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem;">
                        🚨 Critical
                    </div>
                </div>
            </div>
            
            <!-- Model Status -->
            <div style="
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 0.75rem;
                background: rgba(88, 166, 255, 0.05);
                border-radius: 8px;
                font-size: 0.9rem;
                margin-bottom: 1rem;
            ">
                <span style="color: var(--text-secondary);">
                    🧠 AI Engine: <strong>${modelStatus.model_type}</strong>
                </span>
                <span style="
                    padding: 0.25rem 0.75rem;
                    border-radius: 12px;
                    font-weight: 600;
                    ${modelStatus.is_trained ? 
                        'background: rgba(46, 213, 115, 0.2); color: #2ed573;' : 
                        'background: rgba(255, 165, 2, 0.2); color: #ffa502;'}
                ">
                    ${modelStatus.is_trained ? '✅ Active' : '⏳ Learning'}
                </span>
            </div>
            
            ${modelStatus.user_profiles > 0 ? `
            <div style="
                font-size: 0.85rem;
                color: var(--text-secondary);
                text-align: center;
                margin-bottom: 1rem;
            ">
                Learning from ${modelStatus.user_profiles} user${modelStatus.user_profiles > 1 ? 's' : ''} behavior patterns
            </div>
            ` : ''}
            
            <!-- ✅ RECENT THREAT SCORES SECTION (FIXED PLACEMENT) -->
            <div style="
                padding: 1rem;
                background: rgba(88, 166, 255, 0.05);
                border-radius: 8px;
                border: 1px solid rgba(88, 166, 255, 0.2);
            ">
                <h4 style="font-size: 0.9rem; margin-bottom: 0.75rem; color: var(--text-secondary); font-weight: 600;">
                    📊 Recent Login Threat Scores
                </h4>
                <div id="recent-threats-list" style="
                    display: flex;
                    flex-direction: column;
                    gap: 0.5rem;
                ">
                    <div style="text-align: center; color: var(--text-secondary); font-size: 0.85rem;">
                        Loading threat scores...
                    </div>
                </div>
            </div>
        </div>
    `;
    
    const dashboardContent = document.querySelector('.dashboard-content');
    if (dashboardContent) {
        dashboardContent.insertAdjacentHTML('beforeend', aiStatsHTML);
        
        // Load threat scores after HTML is inserted
        setTimeout(() => {
            loadRecentThreatScores();
        }, 200);
    }
}

// ===== REPLACE YOUR ENTIRE loadRecentThreatScores FUNCTION WITH THIS =====

async function loadRecentThreatScores() {
    const listElement = document.getElementById('recent-threats-list');
    
    if (!listElement) {
        console.error('❌ Threat scores list element not found');
        return;
    }
    
    try {
        const response = await fetch('/api/security/dashboard', {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        
        console.log('📊 Dashboard data:', data);
        
        if (data.success && data.dashboard && data.dashboard.recent_events) {
            const aiEvents = data.dashboard.recent_events
                .filter(e => e.type === 'AI_THREAT_ANALYSIS')
                .slice(0, 5);
            
            console.log('🤖 AI Events found:', aiEvents.length);
            
            if (aiEvents.length > 0) {
                listElement.innerHTML = aiEvents.map(event => {
                    // Extract score from description
                    const scoreMatch = event.description.match(/Score (\d+)/);
                    const score = scoreMatch ? parseInt(scoreMatch[1]) : 0;
                    
                    // Determine threat level based on realistic thresholds
                    let color, icon, levelText, bgColor;
                    if (score >= 61) {  // CRITICAL
                        color = '#ff4757';
                        icon = '🚨';
                        levelText = 'CRITICAL';
                        bgColor = 'rgba(255, 71, 87, 0.1)';
                    } else if (score >= 31) {  // SUSPICIOUS
                        color = '#ffa502';
                        icon = '⚠️';
                        levelText = 'SUSPICIOUS';
                        bgColor = 'rgba(255, 165, 2, 0.1)';
                    } else {  // SAFE
                        color = '#2ed573';
                        icon = '✅';
                        levelText = 'Safe';
                        bgColor = 'rgba(46, 213, 115, 0.1)';
                    }
                    
                    // Format timestamp
                    const timestamp = new Date(event.timestamp).toLocaleString('en-US', {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                    });
                    
                    return `
                        <div style="
                            display: flex;
                            justify-content: space-between;
                            align-items: center;
                            padding: 0.75rem;
                            background: ${bgColor};
                            border-radius: 8px;
                            border-left: 3px solid ${color};
                            margin-bottom: 0.5rem;
                        ">
                            <div style="display: flex; flex-direction: column; gap: 0.25rem;">
                                <span style="font-size: 0.75rem; color: var(--text-secondary);">
                                    ${timestamp}
                                </span>
                                <span style="font-size: 0.85rem; color: ${color}; font-weight: 700;">
                                    ${levelText}
                                </span>
                            </div>
                            <div style="
                                display: flex;
                                align-items: center;
                                gap: 0.5rem;
                            ">
                                <span style="font-size: 1.5rem;">${icon}</span>
                                <span style="
                                    font-weight: 700;
                                    font-size: 1.3rem;
                                    color: ${color};
                                ">
                                    ${score}/100
                                </span>
                            </div>
                        </div>
                    `;
                }).join('');
            } else {
                listElement.innerHTML = `
                    <div style="
                        text-align: center; 
                        color: var(--text-secondary); 
                        font-size: 0.85rem;
                        padding: 1rem;
                    ">
                        No threat analyses recorded yet.<br>
                        <span style="font-size: 0.75rem; opacity: 0.7;">
                            AI will analyze your next login
                        </span>
                    </div>
                `;
            }
        } else {
            throw new Error('Invalid response structure');
        }
    } catch (error) {
        console.error('❌ Failed to load threat scores:', error);
        listElement.innerHTML = `
            <div style="
                text-align: center; 
                color: #ff4757; 
                font-size: 0.85rem;
                padding: 1rem;
            ">
                ⚠️ Failed to load threat scores<br>
                <span style="font-size: 0.75rem; opacity: 0.7;">
                    ${error.message}
                </span>
            </div>
        `;
    }
}

// =======================================================
// AI Guardian Banner Display (NEW FUNCTION)
// =======================================================
function displayAIThreatAlert(ai) {
    if (!ai || !ai.threat_analysis) return;

    const threat = ai.threat_analysis;
    const score = threat.threat_score;
    const level = threat.threat_level;
    const message = ai.message || ai.user_message || "AI analysis complete";

    let alertBox = document.getElementById("ai-alert-box");

    // Create banner if missing
    if (!alertBox) {
        alertBox = document.createElement("div");
        alertBox.id = "ai-alert-box";
        document.body.prepend(alertBox);
    }

    // Styling by threat level
    if (level === "critical") {
        alertBox.className = "ai-alert critical";
    } else if (level === "suspicious") {
        alertBox.className = "ai-alert warning";
    } else {
        alertBox.className = "ai-alert safe";
    }

    alertBox.innerHTML = `
        <strong>AI Guardian:</strong> ${message}
        <br><small>Threat Score: ${score} | Level: ${level}</small>
    `;

    // Auto-hide for safe logins
    if (level === "safe") {
        setTimeout(() => {
            alertBox.style.opacity = 0;
            setTimeout(() => alertBox.remove(), 800);
        }, 6000);
    }
}

// Show AI threat notification on login
function handleAIThreatAlert(aiAnalysis) {
    if (!aiAnalysis) return;
    
    const threat = aiAnalysis;
    const reasons = threat.reasons || [];
    
    if (threat.threat_level === 'critical') {
        showNotification(
            `🚨 CRITICAL: ${reasons.join(', ')}. Score: ${threat.threat_score}/100`,
            'error'
        );
    } else if (threat.threat_level === 'suspicious') {
        showNotification(
            `⚠️ Suspicious: ${reasons.join(', ')}. Score: ${threat.threat_score}/100`,
            'warning'
        );
    } else if (threat.threat_score > 20) {
        showNotification(
            `✅ Login analyzed: ${reasons.join(', ')}`,
            'info'
        );
    }
}


// Load AI stats when dashboard opens
const dashboardBtn = document.getElementById('securityDashboardBtn');
if (dashboardBtn) {
    const originalClick = dashboardBtn.onclick;
    dashboardBtn.addEventListener('click', () => {
        if (typeof loadSecurityDashboard === 'function') {
            loadSecurityDashboard();
        }
        loadAIThreatStats();
    });
}

// ===========================
// 2FA Modal + Verification
// ===========================

function show2FAModal() {
    const modal = document.getElementById("twofa-modal");
    modal.style.display = "flex";
}

async function verify2FA() {
    const code = document.getElementById("twofa-input").value;

    const res = await fetch("/api/verify-2fa", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ code })
    });

    const data = await res.json();

    if (!data.success) {
        alert("Incorrect 2FA code");
        return;
    }

    // Close modal and reload dashboard
    document.getElementById("twofa-modal").style.display = "none";
    window.location.reload();
}

// Enhance the existing handleAuth function to show AI alerts


// ================================
// AI Guardian Modal Open / Close
// ================================
document.getElementById("aiGuardianBtn")?.addEventListener("click", () => {
    document.getElementById("aiGuardianModal").style.display = "block";
    loadAIDashboard();      // Load AI dashboard data
    loadLastThreat();       // Load last threat analysis
});

document.getElementById("closeAIGuardian")?.addEventListener("click", () => {
    document.getElementById("aiGuardianModal").style.display = "none";
});


// ================================
// LOAD AI DASHBOARD DATA
// ================================
async function loadAIDashboard() {
    try {
        const res = await fetch('/api/ai/dashboard?days=7');
        const data = await res.json();

        if (!data.success) return;

        const stats = data.dashboard.statistics;
        const devices = data.dashboard.devices;

        // Update Stats Boxes
        document.getElementById("aiTotalAnalyses").textContent = stats.total_analyses;
        document.getElementById("aiSafeCount").textContent = stats.safe_count;
        document.getElementById("aiSuspiciousCount").textContent = stats.suspicious_count;
        document.getElementById("aiCriticalCount").textContent = stats.critical_count;

        // Update Device Intelligence
        document.getElementById("trustedDevicesCount").textContent = devices.trusted;
        document.getElementById("newDevicesCount").textContent = devices.new;
        document.getElementById("totalDevicesCount").textContent = devices.total;

        // Update AI Engine Info
        document.getElementById("modelType").textContent = data.dashboard.ai_model.type;
        document.getElementById("modelProfiles").textContent = data.dashboard.ai_model.profiles + " profiles";
        document.getElementById("modelStatus").style.color =
            data.dashboard.ai_model.trained ? "#2ed573" : "#ff4757";

        
    } catch (err) {
        console.error("AI Dashboard Error:", err);
    }
}


// ================================
// LOAD LAST THREAT SCORE
// ================================
async function loadLastThreat() {
    try {
        const res = await fetch('/api/ai/last-threat');
        const data = await res.json();
        const card = document.getElementById("lastThreatBody");

        if (!data.has_data) {
            card.innerHTML = "<p>No threat analysis available.</p>";
            return;
        }

        const t = data.threat;

        card.innerHTML = `
            <div class="last-threat-score level-${t.level}">
                <h1>${t.score}</h1>
                <p>${t.level_text}</p>
                <p>Reason: ${t.reasons}</p>
                <p>IP: ${t.ip_address}</p>
                <p>Time: ${t.timestamp}</p>
            </div>
        `;
    } catch (err) {
        console.error("Last Threat Error:", err);
    }
}



// Find your existing handleAuth in script.js and after successful login, add:


// ================================================================
// AI GUARDIAN SYSTEM - COMPLETE IMPLEMENTATION
// Add this entire section to the END of your script.js file
// ================================================================

// Global chart instances
let threatTimelineChart = null;
let threatDistributionChart = null;

// ================================================================
// AI GUARDIAN - OPEN DASHBOARD
// ================================================================
document.getElementById('aiGuardianBtn')?.addEventListener('click', openAIGuardianDashboard);
document.getElementById('closeAIGuardian')?.addEventListener('click', () => {
    document.getElementById('aiGuardianModal').style.display = 'none';
});

async function openAIGuardianDashboard() {
    try {
        const modal = document.getElementById('aiGuardianModal');
        if (!modal) {
            showNotification('AI Guardian not available', 'error');
            return;
        }
        
        // Show modal with loading state
        modal.style.display = 'block';
        showNotification('Loading AI Guardian Intelligence...', 'info');
        
        // Load all AI data
        await Promise.all([
            loadAIStats(),
            loadLatestThreatAnalysis(),
            loadThreatHistory(),
            loadDeviceIntelligence()
        ]);
        
        showNotification('AI Guardian loaded successfully', 'success');
        
    } catch (error) {
        console.error('AI Guardian error:', error);
        showNotification('Failed to load AI Guardian', 'error');
    }
}

// ================================================================
// LOAD AI STATISTICS
// ================================================================
async function loadAIStats() {
    try {
        const response = await fetch('/api/ai/threat-stats?days=7');
        const data = await response.json();
        
        if (!data.success) {
            throw new Error('Failed to load AI stats');
        }
        
        const stats = data.statistics;
        const modelStatus = data.ai_model_status;
        
        // Update stat cards
        document.getElementById('aiTotalAnalyses').textContent = stats.total_analyses;
        document.getElementById('aiSafeCount').textContent = stats.safe_count;
        document.getElementById('aiSuspiciousCount').textContent = stats.suspicious_count;
        document.getElementById('aiCriticalCount').textContent = stats.critical_count;
        
        // Update model status
        document.getElementById('modelType').textContent = modelStatus.model_type;
        document.getElementById('modelProfiles').textContent = 
            `${modelStatus.user_profiles} user profiles`;
        
        const statusBadge = document.getElementById('modelStatus');
        if (modelStatus.is_trained) {
            statusBadge.textContent = '● Active';
            statusBadge.style.color = '#2ed573';
        } else {
            statusBadge.textContent = '● Learning';
            statusBadge.style.color = '#ffa502';
        }
        
        // Load charts with data
        await loadThreatCharts(stats);
        
    } catch (error) {
        console.error('Failed to load AI stats:', error);
        // Show zeros if no data
        document.getElementById('aiTotalAnalyses').textContent = '0';
        document.getElementById('aiSafeCount').textContent = '0';
        document.getElementById('aiSuspiciousCount').textContent = '0';
        document.getElementById('aiCriticalCount').textContent = '0';
    }
}

// ================================================================
// LOAD THREAT CHARTS
// ================================================================
async function loadThreatCharts(stats) {
    // Load Chart.js if not already loaded
    if (typeof Chart === 'undefined') {
        await loadChartJS();
    }
    
    // Create timeline chart
    createThreatTimelineChart(stats);
    
    // Create distribution chart
    createThreatDistributionChart(stats);
}

// ================================================================
// LOAD CHART.JS DYNAMICALLY
// ================================================================
function loadChartJS() {
    return new Promise((resolve, reject) => {
        if (typeof Chart !== 'undefined') {
            resolve();
            return;
        }
        
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';
        script.onload = () => resolve();
        script.onerror = () => reject(new Error('Failed to load Chart.js'));
        document.head.appendChild(script);
    });
}

// ================================================================
// THREAT TIMELINE CHART
// ================================================================
function createThreatTimelineChart(stats) {
    const canvas = document.getElementById('threatScoreChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Destroy existing chart
    if (threatTimelineChart) {
        threatTimelineChart.destroy();
    }
    
    // Generate mock timeline data (7 days)
    const labels = [];
    const safeData = [];
    const suspiciousData = [];
    const criticalData = [];
    
    for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
        
        // Generate realistic data based on stats
        const dayMultiplier = (7 - i) / 7;
        safeData.push(Math.floor(stats.safe_count * dayMultiplier * (0.8 + Math.random() * 0.4)));
        suspiciousData.push(Math.floor(stats.suspicious_count * dayMultiplier * (0.8 + Math.random() * 0.4)));
        criticalData.push(Math.floor(stats.critical_count * dayMultiplier * (0.8 + Math.random() * 0.4)));
    }
    
    threatTimelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Safe Logins',
                    data: safeData,
                    borderColor: '#2ed573',
                    backgroundColor: 'rgba(46, 213, 115, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Suspicious',
                    data: suspiciousData,
                    borderColor: '#ffa502',
                    backgroundColor: 'rgba(255, 165, 2, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Critical',
                    data: criticalData,
                    borderColor: '#ff4757',
                    backgroundColor: 'rgba(255, 71, 87, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        usePointStyle: true,
                        padding: 15,
                        font: { size: 12, weight: '600' }
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    titleFont: { size: 14, weight: 'bold' },
                    bodyFont: { size: 13 }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { 
                        precision: 0,
                        font: { size: 11 }
                    },
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                },
                x: {
                    ticks: {
                        font: { size: 11 }
                    },
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

// ================================================================
// THREAT DISTRIBUTION CHART
// ================================================================
function createThreatDistributionChart(stats) {
    const canvas = document.getElementById('threatDistributionChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Destroy existing chart
    if (threatDistributionChart) {
        threatDistributionChart.destroy();
    }
    
    threatDistributionChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Safe', 'Suspicious', 'Critical'],
            datasets: [{
                data: [
                    stats.safe_count,
                    stats.suspicious_count,
                    stats.critical_count
                ],
                backgroundColor: [
                    'rgba(46, 213, 115, 0.8)',
                    'rgba(255, 165, 2, 0.8)',
                    'rgba(255, 71, 87, 0.8)'
                ],
                borderColor: [
                    '#2ed573',
                    '#ffa502',
                    '#ff4757'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        font: { size: 13, weight: '600' },
                        usePointStyle: true
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    titleFont: { size: 14, weight: 'bold' },
                    bodyFont: { size: 13 },
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.parsed / total) * 100).toFixed(1);
                            return `${context.label}: ${context.parsed} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// ================================================================
// LOAD LATEST THREAT ANALYSIS
// ================================================================
async function loadLatestThreatAnalysis() {
    try {
        // Get latest security log
        const response = await fetch('/api/security/dashboard');
        const data = await response.json();
        
        if (!data.success) {
            throw new Error('Failed to load latest analysis');
        }
        
        const recentEvents = data.dashboard.recent_events || [];
        const aiEvent = recentEvents.find(e => e.type === 'AI_THREAT_ANALYSIS');
        
        const threatBody = document.getElementById('lastThreatBody');
        
        if (aiEvent) {
            // Parse AI event description
            const desc = aiEvent.description;
            const scoreMatch = desc.match(/Score (\d+)/);
            const levelMatch = desc.match(/Level: (\w+)/);
            
            const score = scoreMatch ? scoreMatch[1] : '0';
            const level = levelMatch ? levelMatch[1] : 'safe';
            
            let levelColor = '#2ed573';
            let levelIcon = '✅';
            let levelText = 'SAFE';
            
            if (level === 'critical') {
                levelColor = '#ff4757';
                levelIcon = '🚨';
                levelText = 'CRITICAL';
            } else if (level === 'suspicious') {
                levelColor = '#ffa502';
                levelIcon = '⚠️';
                levelText = 'SUSPICIOUS';
            }
            
            threatBody.innerHTML = `
                <div style="padding: 1.5rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <div>
                            <div style="font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
                                ${formatTimestamp(aiEvent.timestamp)}
                            </div>
                            <div style="font-size: 2.5rem; font-weight: 700; color: ${levelColor};">
                                ${score}<span style="font-size: 1.5rem;">/100</span>
                            </div>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-size: 2rem; margin-bottom: 0.5rem;">${levelIcon}</div>
                            <div style="
                                background: ${levelColor}22;
                                color: ${levelColor};
                                padding: 0.5rem 1rem;
                                border-radius: 20px;
                                font-weight: 700;
                                font-size: 0.9rem;
                            ">
                                ${levelText}
                            </div>
                        </div>
                    </div>
                    <div style="
                        background: var(--glass-bg);
                        padding: 1rem;
                        border-radius: 8px;
                        font-size: 0.9rem;
                        color: var(--text-secondary);
                    ">
                        ${aiEvent.description}
                    </div>
                </div>
            `;
        } else {
            threatBody.innerHTML = `
                <div style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                    <div style="font-size: 3rem; margin-bottom: 1rem;">🤖</div>
                    <div style="font-size: 1.1rem; font-weight: 600; margin-bottom: 0.5rem;">
                        No Threat Analysis Yet
                    </div>
                    <div style="font-size: 0.9rem;">
                        AI Guardian will analyze your next login
                    </div>
                </div>
            `;
        }
        
    } catch (error) {
        console.error('Failed to load latest threat:', error);
        document.getElementById('lastThreatBody').innerHTML = `
            <div style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                <div>Unable to load latest analysis</div>
            </div>
        `;
    }
}

// ================================================================
// LOAD THREAT HISTORY TABLE
// ================================================================
async function loadThreatHistory() {
    try {
        const response = await fetch('/api/security/dashboard');
        const data = await response.json();
        
        if (!data.success) {
            throw new Error('Failed to load threat history');
        }
        
        const recentEvents = data.dashboard.recent_events || [];
        const aiEvents = recentEvents.filter(e => e.type === 'AI_THREAT_ANALYSIS');
        
        const historyTable = document.getElementById('aiHistoryTable');
        
        if (aiEvents.length === 0) {
            historyTable.innerHTML = `
                <div style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                    <div style="font-size: 2rem; margin-bottom: 0.5rem;">📋</div>
                    <div>No threat analysis history yet</div>
                </div>
            `;
            return;
        }
        
        historyTable.innerHTML = `
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="border-bottom: 2px solid var(--border-color);">
                            <th style="padding: 0.75rem; text-align: left; font-weight: 600;">Time</th>
                            <th style="padding: 0.75rem; text-align: center; font-weight: 600;">Score</th>
                            <th style="padding: 0.75rem; text-align: center; font-weight: 600;">Level</th>
                            <th style="padding: 0.75rem; text-align: left; font-weight: 600;">Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${aiEvents.map(event => {
                            const desc = event.description;
                            const scoreMatch = desc.match(/Score (\d+)/);
                            const levelMatch = desc.match(/Level: (\w+)/);
                            
                            const score = scoreMatch ? scoreMatch[1] : '0';
                            const level = levelMatch ? levelMatch[1] : 'safe';
                            
                            let levelBadge = '';
                            if (level === 'critical') {
                                levelBadge = '<span style="background: rgba(255, 71, 87, 0.2); color: #ff4757; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.8rem; font-weight: 600;">🚨 CRITICAL</span>';
                            } else if (level === 'suspicious') {
                                levelBadge = '<span style="background: rgba(255, 165, 2, 0.2); color: #ffa502; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.8rem; font-weight: 600;">⚠️ SUSPICIOUS</span>';
                            } else {
                                levelBadge = '<span style="background: rgba(46, 213, 115, 0.2); color: #2ed573; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.8rem; font-weight: 600;">✅ SAFE</span>';
                            }
                            
                            return `
                                <tr style="border-bottom: 1px solid var(--border-color);">
                                    <td style="padding: 0.75rem; font-size: 0.85rem; color: var(--text-secondary);">
                                        ${formatTimestamp(event.timestamp)}
                                    </td>
                                    <td style="padding: 0.75rem; text-align: center; font-weight: 700; font-size: 1.1rem;">
                                        ${score}
                                    </td>
                                    <td style="padding: 0.75rem; text-align: center;">
                                        ${levelBadge}
                                    </td>
                                    <td style="padding: 0.75rem; font-size: 0.85rem; color: var(--text-secondary);">
                                        ${desc.substring(0, 80)}...
                                    </td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        `;
        
    } catch (error) {
        console.error('Failed to load threat history:', error);
        document.getElementById('aiHistoryTable').innerHTML = `
            <div style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                <div>Unable to load threat history</div>
            </div>
        `;
    }
}

// ================================================================
// LOAD DEVICE INTELLIGENCE
// ================================================================
async function loadDeviceIntelligence() {
    try {
        const response = await fetch('/api/devices');
        const data = await response.json();
        
        if (!data.success) {
            throw new Error('Failed to load device intelligence');
        }
        
        const devices = data.devices || [];
        const trustedCount = devices.filter(d => d.is_trusted).length;
        const newCount = devices.filter(d => !d.is_trusted).length;
        const totalCount = devices.length;
        
        document.getElementById('trustedDevicesCount').textContent = trustedCount;
        document.getElementById('newDevicesCount').textContent = newCount;
        document.getElementById('totalDevicesCount').textContent = totalCount;
        
    } catch (error) {
        console.error('Failed to load device intelligence:', error);
        document.getElementById('trustedDevicesCount').textContent = '0';
        document.getElementById('newDevicesCount').textContent = '0';
        document.getElementById('totalDevicesCount').textContent = '0';
    }
}

// ================================================================
// HELPER: Format timestamp for display
// ================================================================
function formatTimestamp(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffHours < 1) {
        return 'Just now';
    } else if (diffHours < 24) {
        return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    } else if (diffDays < 7) {
        return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    } else {
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    }
}

// if (data.ai_threat_analysis) {
//     handleAIThreatAlert(data.ai_threat_analysis);
// }
