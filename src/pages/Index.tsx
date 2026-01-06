import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';
import PageTransition from '@/components/Ghost/PageTransition';
import HeroSection from '@/components/Ghost/HeroSection';
import FeaturesSection from '@/components/Ghost/FeaturesSection';
import TransparencySection from '@/components/Ghost/TransparencySection';

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <PageTransition>
        <main>
          <HeroSection />
          <FeaturesSection />
          <TransparencySection />
        </main>
      </PageTransition>
      <Footer />
    </div>
  );
};

export default Index;
