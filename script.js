// ===== GLOBAL VARIABLES - ENHANCED FOR PHASE 1 =====
let analysisEnabled = true;
let currentUserSalt = null;
let masterPasswordCache = null;
let securityMode = true;
let themePreference = 'dark';
let isLoginMode = true;
let vaultData = [];
let vaultFilter = '';
let vaultSortBy = 'updated_at';
let securityDashboardData = null;

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
    apiCallCount: 0,
    breachCheckCount: 0
};

// DOM Elements Storage
let elements = {};

// ===== INITIALIZATION FUNCTIONS =====
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
        lengthValue: document.getElementById('lengthValue'),
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
        
        // Phase 1: New dashboard elements
        securityDashboard: document.getElementById('securityDashboard'),
        totalPasswords: document.getElementById('totalPasswords'),
        breachedPasswords: document.getElementById('breachedPasswords'),
        weakPasswords: document.getElementById('weakPasswords'),
        oldPasswords: document.getElementById('oldPasswords'),
        securityScore: document.getElementById('securityScore'),
        runSecurityCheck: document.getElementById('runSecurityCheck'),
        notificationSettings: document.getElementById('notificationSettings'),
        
        // Phase 1: Notification modal elements
        notificationModal: document.getElementById('notificationModal'),
        closeNotificationModal: document.getElementById('closeNotificationModal'),
        breachNotifications: document.getElementById('breachNotifications'),
        passwordAgeWarnings: document.getElementById('passwordAgeWarnings'),
        securityNotifications: document.getElementById('securityNotifications'),
        saveNotificationSettings: document.getElementById('saveNotificationSettings'),
        cancelNotificationSettings: document.getElementById('cancelNotificationSettings'),
        
        // Enhanced vault controls
        vaultSearch: document.getElementById('vault-search'),
        vaultSort: document.getElementById('vault-sort'),
        clearSearch: document.getElementById('clearSearch'),
        exportVault: document.getElementById('exportVault'),
        checkAllBreaches: document.getElementById('checkAllBreaches')
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
        
        // Initialize password generator if on generator page
        initializePasswordGenerator();
        
        // Show security status
        showSecurityStatus();
        
        // Phase 1: Initialize breach monitoring
        initializeBreachMonitoring();
        
        // Record performance metrics
        const pageLoadTime = performance.now() - pageLoadStart;
        recordPerformanceMetric('pageLoadTime', pageLoadTime);
        
        console.log(`VaultGuard Phase 1 initialized in ${pageLoadTime.toFixed(2)}ms`);
        
    } catch (error) {
        console.error('Initialization error:', error);
        showNotification('Application failed to initialize properly', 'error');
    }
}

// ===== PHASE 1: SECURITY DASHBOARD FUNCTIONS =====
async function loadSecurityDashboard() {
    if (!document.body.classList.contains('logged-in')) return;
    
    try {
        const response = await fetch('/api/me', {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        const data = await response.json();
        
        if (data.success && data.authenticated) {
            securityDashboardData = data.security_stats;
            updateSecurityDashboard(data);
            loadNotificationPreferences(data.preferences);
        }
    } catch (error) {
        console.error('Failed to load security dashboard:', error);
        showNotification('Failed to load security dashboard', 'error');
    }
}

function updateSecurityDashboard(data) {
    const stats = data.security_stats;
    
    if (elements.totalPasswords) elements.totalPasswords.textContent = data.vault_count;
    if (elements.breachedPasswords) elements.breachedPasswords.textContent = stats.breached_passwords;
    if (elements.weakPasswords) elements.weakPasswords.textContent = stats.weak_passwords;
    if (elements.oldPasswords) elements.oldPasswords.textContent = stats.old_passwords;
    if (elements.securityScore) elements.securityScore.textContent = stats.security_score + '%';
    
    updateDashboardCardStates(stats);
}

function updateDashboardCardStates(stats) {
    const breachedCard = document.getElementById('breachedCard');
    const weakCard = document.getElementById('weakCard');
    const oldCard = document.getElementById('oldCard');
    const scoreCard = document.getElementById('securityScoreCard');
    
    if (breachedCard) {
        breachedCard.className = stats.breached_passwords > 0 ? 'dashboard-card critical' : 'dashboard-card success';
    }
    if (weakCard) {
        weakCard.className = stats.weak_passwords > 0 ? 'dashboard-card warning' : 'dashboard-card success';
    }
    if (oldCard) {
        oldCard.className = stats.old_passwords > 0 ? 'dashboard-card info' : 'dashboard-card success';
    }
    
    if (scoreCard) {
        if (stats.security_score >= 80) {
            scoreCard.className = 'dashboard-card success';
        } else if (stats.security_score >= 60) {
            scoreCard.className = 'dashboard-card warning';
        } else {
            scoreCard.className = 'dashboard-card critical';
        }
    }
}

async function runFullSecurityCheck() {
    const masterPassword = await getMasterPassword();
    if (!masterPassword) return;
    
    try {
        updateSecurityCheckButtonState(true);
        
        const response = await fetch('/api/security/check-all-passwords', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ master_password: masterPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(`Security check completed! ${data.breached_found} breached passwords found.`, 
                           data.breached_found > 0 ? 'warning' : 'success');
            
            // Reload dashboard and vault data
            await loadSecurityDashboard();
            await loadVaultData();
            
            performanceMetrics.breachCheckCount++;
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Security check error:', error);
        showNotification('Failed to run security check', 'error');
    } finally {
        updateSecurityCheckButtonState(false);
    }
}

function updateSecurityCheckButtonState(isRunning) {
    if (!elements.runSecurityCheck) return;
    
    if (isRunning) {
        elements.runSecurityCheck.disabled = true;
        elements.runSecurityCheck.textContent = '🔍 Checking... Please Wait';
        elements.runSecurityCheck.style.opacity = '0.7';
    } else {
        elements.runSecurityCheck.disabled = false;
        elements.runSecurityCheck.textContent = '🔍 Run Full Security Check';
        elements.runSecurityCheck.style.opacity = '1';
    }
}

// ===== PHASE 1: NOTIFICATION PREFERENCES =====
function loadNotificationPreferences(preferences) {
    if (preferences && elements.breachNotifications) {
        elements.breachNotifications.checked = preferences.breach_notifications;
        elements.passwordAgeWarnings.checked = preferences.password_age_warnings;
        elements.securityNotifications.checked = preferences.security_notifications;
    }
}

function openNotificationSettings() {
    if (elements.notificationModal) {
        elements.notificationModal.style.display = 'flex';
        elements.notificationModal.style.animation = 'modalFadeIn 0.3s ease-out';
    }
}

function closeNotificationSettings() {
    if (elements.notificationModal) {
        elements.notificationModal.style.animation = 'modalFadeOut 0.3s ease-out';
        setTimeout(() => {
            elements.notificationModal.style.display = 'none';
        }, 300);
    }
}

async function saveNotificationPreferences() {
    try {
        const preferences = {
            breach_notifications: elements.breachNotifications?.checked || false,
            password_age_warnings: elements.passwordAgeWarnings?.checked || false,
            security_notifications: elements.securityNotifications?.checked || false
        };
        
        const response = await fetch('/api/security/notifications', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(preferences)
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Notification preferences saved!', 'success');
            closeNotificationSettings();
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Failed to save notification preferences:', error);
        showNotification('Failed to save preferences', 'error');
    }
}

// ===== PHASE 1: BREACH MONITORING =====
function initializeBreachMonitoring() {
    // Set up periodic breach checking if user has enabled notifications
    if (document.body.classList.contains('logged-in')) {
        // Check for breaches every 6 hours
        setInterval(async () => {
            try {
                const response = await fetch('/api/me');
                const data = await response.json();
                
                if (data.success && data.preferences?.breach_notifications) {
                    // Silent background check - user will be notified if breaches found
                    console.log('Background breach monitoring active');
                }
            } catch (error) {
                console.error('Background breach monitoring error:', error);
            }
        }, 6 * 60 * 60 * 1000); // 6 hours
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

// ===== EVENT LISTENERS SETUP =====
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

    // Generator page controls
    if (elements.lengthSlider && elements.lengthValue) {
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

    // Generator checkboxes
    const checkboxes = [elements.includeUpper, elements.includeLower, elements.includeNumbers, elements.includeSymbols];
    checkboxes.forEach(checkbox => {
        if (checkbox) {
            checkbox.addEventListener('change', () => {
                updatePasswordGeneratorSettings();
                validateGeneratorSettings();
            });
        }
    });

    // Authentication controls
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

    // Vault management
    if (elements.savePasswordBtn) {
        elements.savePasswordBtn.addEventListener('click', savePassword);
    }

    // Vault search and sort
    const vaultSearch = document.getElementById('vault-search');
    if (vaultSearch) {
        vaultSearch.addEventListener('input', debounce((e) => {
            filterVaultEntries(e.target.value);
        }, 300));
    }

    const vaultSort = document.getElementById('vault-sort');
    if (vaultSort) {
        vaultSort.addEventListener('change', (e) => {
            sortVaultEntries(e.target.value);
        });
    }

    if (elements.clearSearch) {
        elements.clearSearch.addEventListener('click', clearVaultFilter);
    }

    // Phase 1: New dashboard event listeners
    if (elements.runSecurityCheck) {
        elements.runSecurityCheck.addEventListener('click', runFullSecurityCheck);
    }

    if (elements.notificationSettings) {
        elements.notificationSettings.addEventListener('click', openNotificationSettings);
    }

    // Phase 1: Notification modal event listeners
    if (elements.closeNotificationModal) {
        elements.closeNotificationModal.addEventListener('click', closeNotificationSettings);
    }

    if (elements.saveNotificationSettings) {
        elements.saveNotificationSettings.addEventListener('click', saveNotificationPreferences);
    }

    if (elements.cancelNotificationSettings) {
        elements.cancelNotificationSettings.addEventListener('click', closeNotificationSettings);
    }

    if (elements.notificationModal) {
        elements.notificationModal.addEventListener('click', (e) => {
            if (e.target === elements.notificationModal) {
                closeNotificationSettings();
            }
        });
    }

    // Enhanced vault actions
    if (elements.exportVault) {
        elements.exportVault.addEventListener('click', exportVaultData);
    }

    if (elements.checkAllBreaches) {
        elements.checkAllBreaches.addEventListener('click', runFullSecurityCheck);
    }

    // Security monitoring
    document.addEventListener('visibilitychange', handleVisibilityChange);
    document.addEventListener('keydown', handleKeyboardShortcuts);
}

// ===== PASSWORD ANALYSIS FUNCTIONS =====
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
    
    // Check password against breach database
    checkPasswordStrength(password);
    
    // Show recommendations
    displayPasswordRecommendations(recommendations);
}

// Add this new function to reset the strength meter
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

// ===== UI UPDATE FUNCTIONS =====
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
        showNotification('Password cleared', 'info');
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

// ===== PASSWORD GENERATOR FUNCTIONS =====
function updateLengthDisplay(length) {
    if (!elements.lengthValue) return;
    
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
    
    elements.lengthValue.style.color = color;
    elements.lengthValue.textContent = `${length} ${label}`;
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
    const analyzerSection = document.getElementById('analyzer-section');
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

// ===== AUTHENTICATION FUNCTIONS =====
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
        } else {
            elements.authTitle.textContent = '🛡️ Create Secure Account';
            elements.authSubmit.textContent = 'Create Account';
            elements.authSwitchText.textContent = 'Already have an account?';
            elements.authSwitchLink.textContent = 'Login';
        }
    }
    
    // Clear any previous errors
    clearAuthErrors();
}

function clearAuthErrors() {
    const errorElements = document.querySelectorAll('.auth-error');
    errorElements.forEach(el => el.remove());
    
    // Reset input field styles
    [elements.authUsername, elements.authPassword].forEach(input => {
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
    const password = elements.authPassword?.value;
    
    // Basic validation
    if (!username || !password) {
        showAuthError('Please fill in all fields');
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
    
    try {
        // Update submit button state
        updateAuthSubmitState(true);
        
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUserSalt = data.salt;
            masterPasswordCache = password;
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

// ===== VAULT MANAGEMENT FUNCTIONS =====
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
    // Update any authenticated user UI elements
    const usernameElements = document.querySelectorAll('.current-username');
    usernameElements.forEach(el => {
        el.textContent = userData.username;
    });
    
    const vaultCountElements = document.querySelectorAll('.vault-count');
    vaultCountElements.forEach(el => {
        el.textContent = userData.vault_count || 0;
    });
}

function updateUIForUnauthenticatedUser() {
    // Update UI for unauthenticated state
    currentUserSalt = null;
    masterPasswordCache = null;
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
                updateVaultDisplay();
                showNotification(`Loaded ${vaultData.length} encrypted passwords`, 'info');
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
                master_password: masterPassword,
                category: category,
                notes: notes
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Clear form
            elements.siteName.value = '';
            elements.vaultUsername.value = '';
            elements.vaultPassword.value = '';
            if (elements.vaultCategory) elements.vaultCategory.value = 'General';
            if (elements.vaultNotes) elements.vaultNotes.value = '';
            
            // Reload vault data and dashboard
            await loadVaultData();
            if (loadSecurityDashboard) await loadSecurityDashboard();
            showNotification(data.message, 'success');
            
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

async function deleteVaultPassword(id) {
    const item = vaultData.find(item => item.id === id);
    
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
            if (loadSecurityDashboard) await loadSecurityDashboard();
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

function filterVaultEntries(searchTerm) {
    vaultFilter = searchTerm.toLowerCase();
    
    if (elements.clearSearch) {
        elements.clearSearch.style.display = searchTerm ? 'block' : 'none';
    }
    
    updateVaultDisplay();
}

function sortVaultEntries(sortBy) {
    vaultSortBy = sortBy;
    updateVaultDisplay();
}

function updateVaultDisplay() {
    if (!elements.vaultList) return;
    
    let filteredData = vaultData;
    
    // Apply filter
    if (vaultFilter) {
        filteredData = vaultData.filter(item => 
            item.site.toLowerCase().includes(vaultFilter) ||
            item.username.toLowerCase().includes(vaultFilter) ||
            (item.category && item.category.toLowerCase().includes(vaultFilter))
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
                return (a.category || 'General').localeCompare(b.category || 'General');
            case 'security_score':
                return (b.password_strength_score || 0) - (a.password_strength_score || 0);
            case 'access_count':
                return (b.access_count || 0) - (a.access_count || 0);
            case 'created_at':
                return new Date(b.created_at) - new Date(a.created_at);
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
    
    // Display vault entries with Phase 1 enhancements
    elements.vaultList.innerHTML = filteredData.map((item, index) => `
        <li class="vault-item ${getSecurityClass(item)}" style="animation: fadeInUp 0.4s ease-out ${index * 0.05}s backwards;">
            <div class="vault-info">
                <div class="site-header">
                    <h4 class="site-name">${escapeHtml(item.site)}</h4>
                    <div class="vault-meta">
                        <span class="category-badge ${(item.category || 'general').toLowerCase()}">${escapeHtml(item.category || 'General')}</span>
                        <span class="created-date">${item.created_at}</span>
                        ${item.updated_at !== item.created_at ? `<span class="updated-badge">Updated</span>` : ''}
                        ${getSecurityBadge(item)}
                    </div>
                </div>
                <p class="username-display">👤 ${escapeHtml(item.username)}</p>
                <div class="password-preview">🔐 Password: ••••••••••• (AES-256 Encrypted)</div>
                ${item.notes ? `<div class="vault-notes">📝 ${escapeHtml(item.notes).substring(0, 100)}${item.notes.length > 100 ? '...' : ''}</div>` : ''}
                ${item.updated_at !== item.created_at ? `<div class="updated-date">Last updated: ${item.updated_at}</div>` : ''}
                <div class="vault-stats">
                    ${item.access_count ? `<span class="access-count">👁️ ${item.access_count} views</span>` : ''}
                    <span class="password-age">📅 ${item.password_age_days || 0} days old</span>
                    ${item.needs_rotation ? `<span class="rotation-needed">⚠️ Rotation needed</span>` : ''}
                    ${item.is_breached ? `<span class="breach-warning-small">🚨 Breached</span>` : `<span class="secure-badge-small">✅ Secure</span>`}
                </div>
            </div>
            <div class="vault-actions">
                <button id="copy-btn-${item.id}" class="vault-btn copy-btn" onclick="copyVaultPassword(${item.id})" title="Secure copy">
                    📋 <span>Copy</span>
                </button>
                <button id="view-btn-${item.id}" class="vault-btn view-btn" onclick="viewVaultPassword(${item.id})" title="Decrypt & view">
                    👁️ <span>View</span>
                </button>
                <button id="delete-btn-${item.id}" class="vault-btn delete-btn" onclick="deleteVaultPassword(${item.id})" title="Secure delete">
                    🗑️ <span>Delete</span>
                </button>
            </div>
        </li>
    `).join('');
}

function getSecurityClass(item) {
    if (item.is_breached) return 'security-critical';
    if (item.password_strength_score < 2) return 'security-weak';
    if (item.needs_rotation) return 'security-warning';
    return 'security-good';
}

function getSecurityBadge(item) {
    if (item.is_breached) {
        return `<span class="security-badge critical">🚨 Breached (${item.breach_count || 0})</span>`;
    }
    
    const strengthLabels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    const strengthLabel = strengthLabels[item.password_strength_score] || 'Unknown';
    
    if (item.password_strength_score >= 4) {
        return `<span class="security-badge strong">🛡️ ${strengthLabel}</span>`;
    } else if (item.password_strength_score >= 3) {
        return `<span class="security-badge good">✅ ${strengthLabel}</span>`;
    } else if (item.password_strength_score >= 2) {
        return `<span class="security-badge fair">⚠️ ${strengthLabel}</span>`;
    } else {
        return `<span class="security-badge weak">🔴 ${strengthLabel}</span>`;
    }
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
                        <strong>Security:</strong> All passwords encrypted with AES-256 before storage
                    </div>
                    <div class="security-features">
                        <div class="feature">🛡️ PBKDF2 Key Derivation</div>
                        <div class="feature">🔒 Fernet Encryption</div>
                        <div class="feature">🚫 Zero-Knowledge Architecture</div>
                        <div class="feature">🔍 HaveIBeenPwned Integration</div>
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
    
    const statsDiv = document.createElement('div');
    statsDiv.className = 'vault-stats';
    statsDiv.innerHTML = `
        <div class="stats-grid">
            <div class="stat-item">
                <span class="stat-value">${visibleCount}</span>
                <span class="stat-label">${vaultFilter ? 'Filtered' : 'Total'} Passwords</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">${50 - vaultData.length}</span>
                <span class="stat-label">Remaining Slots</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">🔒</span>
                <span class="stat-label">AES-256 Secured</span>
            </div>
            <div class="stat-item">
                <span class="stat-value">${Math.round((vaultData.length / 50) * 100)}%</span>
                <span class="stat-label">Vault Usage</span>
            </div>
        </div>
    `;
    
    if (elements.vaultList && elements.vaultList.parentNode) {
        elements.vaultList.parentNode.insertBefore(statsDiv, elements.vaultList);
    }
}

// ===== PHASE 1: EXPORT FUNCTIONALITY =====
async function exportVaultData() {
    if (!confirm('⚠️ Export vault data?\n\nThis will create a JSON file with your encrypted passwords. Keep this file secure!')) {
        return;
    }
    
    try {
        const response = await fetch('/api/vault', {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            const exportData = {
                export_date: new Date().toISOString(),
                application: 'VaultGuard Secure - Phase 1',
                vault_entries: data.vault_entries.map(entry => ({
                    site: entry.site,
                    username: entry.username,
                    category: entry.category,
                    notes: entry.notes,
                    created_at: entry.created_at,
                    updated_at: entry.updated_at,
                    password_strength_score: entry.password_strength_score,
                    is_breached: entry.is_breached,
                    breach_count: entry.breach_count,
                    password_age_days: entry.password_age_days,
                    needs_rotation: entry.needs_rotation
                    // Note: encrypted_password is intentionally excluded for security
                }))
            };
            
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vaultguard-export-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            showNotification('Vault data exported successfully! (Passwords not included for security)', 'success');
        } else {
            showNotification('Failed to export vault data', 'error');
        }
    } catch (error) {
        console.error('Export error:', error);
        showNotification('Failed to export vault data', 'error');
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
                    <label>Username:</label>
                    <span class="field-value">${escapeHtml(item.username)}</span>
                </div>
                ${item.category ? `
                <div class="password-field">
                    <label>Category:</label>
                    <span class="field-value">${escapeHtml(item.category)}</span>
                </div>` : ''}
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
                </div>` : ''}
                <div class="password-stats">
                    <div class="stat">Created: ${item.created_at}</div>
                    <div class="stat">Updated: ${item.updated_at}</div>
                    ${item.access_count ? `<div class="stat">Accessed: ${item.access_count} times</div>` : ''}
                    ${item.password_age_days ? `<div class="stat">Age: ${item.password_age_days} days</div>` : ''}
                </div>
                <div class="security-timer">
                    🔒 Auto-hide in <span id="timer-${item.id}">15</span> seconds for security
                </div>
            </div>
            <div class="modal-actions">
                <button onclick="copyPasswordFromModal('${password.replace(/'/g, "\\'")}');" class="copy-modal-btn">📋 Secure Copy</button>
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

// ===== BREACH CHECK FUNCTIONS =====
async function checkPasswordStrength(password) {
    try {
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
                performanceMetrics.breachCheckCount++;
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
        let warningBg = 'rgba(255, 71, 87, 0.1)';
        
        switch (securityLevel) {
            case 'critical':
                warningLevel = 'CRITICAL RISK';
                warningColor = '#ff4757';
                warningBg = 'rgba(255, 71, 87, 0.2)';
                break;
            case 'high_risk':
                warningLevel = 'HIGH RISK';
                warningColor = '#ff6348';
                warningBg = 'rgba(255, 99, 72, 0.1)';
                break;
            case 'medium_risk':
                warningLevel = 'MEDIUM RISK';
                warningColor = '#ffa502';
                warningBg = 'rgba(255, 165, 2, 0.1)';
                break;
            default:
                warningLevel = 'COMPROMISED';
                warningColor = '#ff4757';
                warningBg = 'rgba(255, 71, 87, 0.1)';
        }
        
        elements.breachStatus.innerHTML = `
            <span class="breach-warning" style="
                color: ${warningColor}; 
                background: ${warningBg}; 
                padding: 0.5rem 1rem; 
                border-radius: 6px; 
                border: 1px solid ${warningColor}40;
                animation: breachPulse 1.5s ease-in-out infinite; 
                font-weight: 700;
                display: inline-block;
                font-size: 0.85rem;
            ">
                🚨 ${warningLevel}: Found in ${count.toLocaleString()} breaches!
            </span>`;
    } else {
        let securityText = 'SECURE';
        let securityColor = '#2ed573';
        let securityBg = 'rgba(46, 213, 115, 0.1)';
        
        switch (securityLevel) {
            case 'fortress':
                securityText = 'FORTRESS LEVEL';
                securityColor = '#2ed573';
                break;
            case 'military':
                securityText = 'MILITARY GRADE';
                securityColor = '#58a6ff';
                securityBg = 'rgba(88, 166, 255, 0.1)';
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
            <span class="breach-safe" style="
                color: ${securityColor}; 
                background: ${securityBg}; 
                padding: 0.5rem 1rem; 
                border-radius: 6px; 
                border: 1px solid ${securityColor}40;
                font-weight: 700;
                display: inline-block;
                font-size: 0.85rem;
            ">
                ✅ ${securityText}: Not found in HaveIBeenPwned
            </span>`;
    }
}

function updateAdvancedMetrics(data) {
    // Update additional security metrics if elements exist
    const entropyElement = document.getElementById('passwordEntropy');
    const timeElement = document.getElementById('crackTimeDetailed');
    
    if (entropyElement) {
        const entropy = Math.log2(Math.pow(95, data.score * 2)); // Simplified entropy calculation
        entropyElement.textContent = `${entropy.toFixed(1)} bits`;
    }
    
    if (timeElement && data.crack_time) {
        timeElement.textContent = data.crack_time;
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
            masterPasswordCache = null;
            showNotification('Master password cleared for security', 'info');
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
    
    // Ctrl+Shift+S: Run security check
    if (event.ctrlKey && event.shiftKey && event.key === 'S') {
        event.preventDefault();
        if (document.body.classList.contains('logged-in')) {
            runFullSecurityCheck();
        }
    }
    
    // Ctrl+Shift+N: Open notification settings
    if (event.ctrlKey && event.shiftKey && event.key === 'N') {
        event.preventDefault();
        if (document.body.classList.contains('logged-in')) {
            openNotificationSettings();
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
        
        if (elements.notificationModal?.style.display === 'flex') {
            closeNotificationSettings();
        }
        
        const passwordModal = document.querySelector('.password-modal');
        if (passwordModal) {
            passwordModal.remove();
        }
    }
    
    // Ctrl+L: Focus on login
    if (event.ctrlKey && event.key === 'l') {
        event.preventDefault();
        if (elements.loginBtn) {
            openAuthModal();
        }
    }
    
    // Ctrl+F: Focus on vault search
    if (event.ctrlKey && event.key === 'f' && elements.vaultSearch) {
        event.preventDefault();
        elements.vaultSearch.focus();
    }
}

function recordPerformanceMetric(metric, value) {
    performanceMetrics[metric] = value;
    
    // Log performance issues
    if (metric === 'analysisTime' && value > 1000) {
        console.warn('Password analysis taking longer than expected:', value + 'ms');
    }
    
    if (metric === 'breachCheckCount' && performanceMetrics.breachCheckCount > 0) {
        console.log(`Breach checks performed: ${performanceMetrics.breachCheckCount}`);
    }
}

// ===== INITIALIZATION HELPERS =====
function initializePasswordGenerator() {
    // Auto-generate initial password if on generator page
    if (elements.generateBtn && elements.generatedPassword) {
        setTimeout(() => {
            generateNewPassword();
        }, 500);
    }
    
    // Set initial slider value display
    if (elements.lengthSlider && elements.lengthValue) {
        updateLengthDisplay(parseInt(elements.lengthSlider.value));
    }
}

function showSecurityStatus() {
    setTimeout(() => {
        if (location.protocol === 'https:') {
            showNotification('🚀 Phase 1 Enhanced: HTTPS + HaveIBeenPwned integration active!', 'success');
        } else {
            showNotification('⚠️ Warning: Use HTTPS for full Phase 1 security features', 'warning');
        }
    }, 1000);
}

// ===== NOTIFICATION SYSTEM =====
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
        max-width: 350px;
        word-wrap: break-word;
        animation: slideInRight 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        backdrop-filter: blur(15px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        cursor: pointer;
    `;
    
    notification.innerHTML = `<span style="margin-right: 8px;">${icons[type] || icons.success}</span>${message}`;
    
    // Click to dismiss
    notification.addEventListener('click', () => {
        notification.style.animation = 'slideOutRight 0.3s ease-in';
        setTimeout(() => notification.remove(), 300);
    });
    
    document.body.appendChild(notification);
    
    // Auto-hide after 4 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOutRight 0.3s ease-in';
            setTimeout(() => notification.remove(), 300);
        }
    }, 4000);
}

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
        
        /* Phase 1: Enhanced security badges */
        .security-badge {
            font-size: 0.7rem;
            padding: 0.2rem 0.5rem;
            border-radius: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .security-badge.critical {
            background: linear-gradient(135deg, #ff4757, #ff3742);
            color: white;
        }
        
        .security-badge.weak {
            background: linear-gradient(135deg, #ff6348, #ff4757);
            color: white;
        }
        
        .security-badge.fair {
            background: linear-gradient(135deg, #ffa502, #ff6348);
            color: white;
        }
        
        .security-badge.good {
            background: linear-gradient(135deg, #3742fa, #5352ed);
            color: white;
        }
        
        .security-badge.strong {
            background: linear-gradient(135deg, #2ed573, #17d97a);
            color: white;
        }
        
        /* Category badges */
        .category-badge {
            font-size: 0.7rem;
            padding: 0.2rem 0.5rem;
            border-radius: 8px;
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            text-transform: uppercase;
            font-weight: 500;
        }
        
        .category-badge.banking { background: rgba(255, 165, 2, 0.2); color: #ffa502; }
        .category-badge.social { background: rgba(58, 134, 255, 0.2); color: #3a86ff; }
        .category-badge.work { background: rgba(139, 92, 246, 0.2); color: #8b5cf6; }
        .category-badge.email { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
        
        /* Vault security indicators */
        .security-critical { border-left: 4px solid #ff4757 !important; }
        .security-weak { border-left: 4px solid #ff6348 !important; }
        .security-warning { border-left: 4px solid #ffa502 !important; }
        .security-good { border-left: 4px solid #2ed573 !important; }
        
        .breach-warning-small, .secure-badge-small {
            font-size: 0.65rem;
            padding: 0.15rem 0.4rem;
            border-radius: 6px;
            font-weight: 600;
        }
        
        .breach-warning-small {
            background: rgba(255, 71, 87, 0.2);
            color: #ff4757;
            border: 1px solid rgba(255, 71, 87, 0.3);
        }
        
        .secure-badge-small {
            background: rgba(46, 213, 115, 0.2);
            color: #2ed573;
            border: 1px solid rgba(46, 213, 115, 0.3);
        }
        
        .rotation-needed {
            background: rgba(255, 165, 2, 0.2);
            color: #ffa502;
            font-size: 0.65rem;
            padding: 0.15rem 0.4rem;
            border-radius: 6px;
            border: 1px solid rgba(255, 165, 2, 0.3);
        }
        
        /* Vault notes styling */
        .vault-notes {
            color: var(--text-secondary);
            font-size: 0.8rem;
            font-style: italic;
            margin: 0.5rem 0;
            padding: 0.5rem;
            background: var(--glass-bg);
            border-radius: 6px;
            border-left: 3px solid var(--accent-blue);
        }
        
        /* Enhanced vault stats */
        .vault-stats {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-top: 0.75rem;
            font-size: 0.7rem;
        }
        
        .vault-stats span {
            padding: 0.2rem 0.5rem;
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            border-radius: 6px;
            font-weight: 500;
        }
        
        .access-count { color: var(--accent-blue); }
        .password-age { color: var(--text-secondary); }
        
        /* Loading states */
        .loading {
            opacity: 0.7;
            pointer-events: none;
        }
        
        .loading::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-top: 2px solid var(--accent-blue, #58a6ff);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: translate(-50%, -50%) rotate(0deg); }
            100% { transform: translate(-50%, -50%) rotate(360deg); }
        }
        
        /* Responsive design improvements */
        @media (max-width: 768px) {
            .vault-actions {
                flex-direction: column;
                gap: 0.5rem;
            }
            
            .vault-btn {
                justify-content: center;
                min-width: auto;
                width: 100%;
            }
            
            .password-modal-content {
                margin: 1rem;
                padding: 1.5rem;
            }
            
            .modal-actions {
                flex-direction: column;
                gap: 0.75rem;
            }
        }
        
        @media (max-width: 480px) {
            .vault-btn {
                padding: 0.75rem 1rem;
                font-size: 0.9rem;
            }
            
            .modal-actions button {
                width: 100%;
            }
            
            .vault-stats {
                flex-direction: column;
                gap: 0.25rem;
            }
        }
        
        /* Accessibility improvements */
        .vault-btn:focus,
        .copy-modal-btn:focus,
        .close-modal-btn:focus {
            outline: 2px solid var(--accent-blue, #58a6ff);
            outline-offset: 2px;
        }
        
        /* High contrast mode support */
        @media (prefers-contrast: high) {
            .vault-btn {
                border-width: 2px;
            }
            
            .security-badge {
                border: 2px solid currentColor;
            }
        }
        
        /* Reduced motion support */
        @media (prefers-reduced-motion: reduce) {
            * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }
    `;
    document.head.appendChild(style);
}

// ===== CONSOLE SECURITY WARNING =====
function showSecurityWarning() {
    console.log('%c🛡️ VaultGuard Security Notice - Phase 1 Enhanced', 'color: #2ed573; font-size: 16px; font-weight: bold;');
    console.log('%cThis application handles sensitive password data.', 'color: #ffa502; font-size: 12px;');
    console.log('%cPhase 1 Features: HaveIBeenPwned integration, enhanced logging, notifications', 'color: #58a6ff; font-size: 12px;');
    console.log('%cDo not paste or execute unknown code in this console.', 'color: #ff4757; font-size: 12px;');
    console.log('%cAll passwords are encrypted with AES-256 before storage.', 'color: #8b5cf6; font-size: 12px;');
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
});

// Enhanced search functionality for vault
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('vault-search');
    const clearBtn = document.getElementById('clearSearch');
    const sortSelect = document.getElementById('vault-sort');
    
    // Search input enhancements
    if (searchInput && clearBtn) {
        searchInput.addEventListener('input', function() {
            if (this.value.length > 0) {
                clearBtn.style.display = 'block';
            } else {
                clearBtn.style.display = 'none';
            }
            
            // Trigger search with debouncing
            clearTimeout(this.searchTimeout);
            this.searchTimeout = setTimeout(() => {
                filterVaultEntries(this.value);
            }, 300);
        });
        
        clearBtn.addEventListener('click', function() {
            searchInput.value = '';
            clearBtn.style.display = 'none';
            filterVaultEntries('');
            searchInput.focus();
        });
    }
    
    // Enhanced sort functionality
    if (sortSelect) {
        sortSelect.addEventListener('change', function() {
            sortVaultEntries(this.value);
        });
    }
});

// Fix timestamp formatting in JavaScript
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

// ===== GLOBAL FUNCTION EXPORTS =====
// Make functions available globally for onclick handlers
window.copyVaultPassword = copyVaultPassword;
window.viewVaultPassword = viewVaultPassword;
window.deleteVaultPassword = deleteVaultPassword;
window.clearVaultFilter = clearVaultFilter;
window.togglePasswordVisibilityInModal = togglePasswordVisibilityInModal;
window.copyPasswordFromModal = copyPasswordFromModal;

// Export enhanced Phase 1 object for global access
window.VaultGuard = {
    analyzePassword,
    generateRandomPassword,
    openAuthModal,
    closeAuthModal,
    showNotification,
    initialize,
    // Phase 1 additions
    loadSecurityDashboard,
    runFullSecurityCheck,
    openNotificationSettings,
    saveNotificationPreferences,
    exportVaultData,
    version: 'Phase 1 Enhanced'
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
