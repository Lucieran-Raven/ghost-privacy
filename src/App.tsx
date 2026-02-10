import { Suspense, lazy } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import ErrorBoundary from "./components/ErrorBoundary";
import AmbientAura from "./components/Ghost/AmbientAura";
import InstallPrompt from "./components/Ghost/InstallPrompt";
import DecoyRoutes from "./components/Ghost/DecoyRoutes";
import SecurityStatusBar from "./components/Ghost/SecurityStatusBar";
import { usePlausibleDeniability } from "./hooks/usePlausibleDeniability";
import { usePrivacyShield } from "./hooks/usePrivacyShield";
import PrivacyShield from "./components/Ghost/PrivacyShield";

const Index = lazy(() => import("./pages/Index"));
const Session = lazy(() => import("./pages/Session"));
const Security = lazy(() => import("./pages/Security"));
const About = lazy(() => import("./pages/About"));
const Terms = lazy(() => import("./pages/Terms"));
const Contact = lazy(() => import("./pages/Contact"));
const Limitations = lazy(() => import("./pages/Limitations"));
const Contribute = lazy(() => import("./pages/Contribute"));
const Onion = lazy(() => import("./pages/Onion"));
const Tor = lazy(() => import("./pages/Tor"));
const Quarantine = lazy(() => import("./pages/Quarantine"));
const Downloads = lazy(() => import("./pages/Downloads"));
const Calculator = lazy(() => import("./pages/Calculator"));
const NotFound = lazy(() => import("./pages/NotFound"));

const queryClient = new QueryClient();

const App = () => {
  const { isDecoyActive } = usePlausibleDeniability();
  const { isShieldActive, canDismiss, dismiss } = usePrivacyShield();

  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <div className="relative min-h-screen">
            <AmbientAura />
            <div className="relative z-10">
              <SecurityStatusBar />
              <PrivacyShield active={isShieldActive} canDismiss={canDismiss} onDismiss={dismiss} />
              {!isDecoyActive && <Toaster />}
              {!isDecoyActive && <Sonner position="top-center" />}
              <BrowserRouter>
                <Suspense fallback={<div />}>
                  <Routes>
                    <Route path="/" element={<Index />} />
                    <Route path="/session" element={<Session />} />
                    <Route path="/calculator" element={<Calculator />} />
                    <Route path="/security" element={<Security />} />
                    <Route path="/about" element={<About />} />
                    <Route path="/terms" element={<Terms />} />
                    <Route path="/contact" element={<Contact />} />
                    <Route path="/limitations" element={<Limitations />} />
                    <Route path="/contribute" element={<Contribute />} />
                    <Route path="/downloads" element={<Downloads />} />
                    <Route path="/tor" element={<Tor />} />
                    <Route path="/onion" element={<Onion />} />
                    <Route path="/decoy" element={<Quarantine />} />
                    <Route path="/ghost_debug/*" element={<DecoyRoutes type="debug" />} />
                    <Route path="/api/docs" element={<DecoyRoutes type="api" />} />
                    <Route path="/backup/*" element={<DecoyRoutes type="backup" />} />
                    <Route path="/admin" element={<DecoyRoutes type="admin" />} />
                    <Route path="/admin/*" element={<DecoyRoutes type="admin" />} />
                    <Route path="/.env" element={<DecoyRoutes type="env" />} />
                    <Route path="/config/*" element={<DecoyRoutes type="config" />} />
                    <Route path="*" element={<NotFound />} />
                  </Routes>
                </Suspense>
                {!isDecoyActive && <InstallPrompt showAfterMs={10000} position="bottom" />}
              </BrowserRouter>
            </div>
          </div>
        </TooltipProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
};

export default App;
