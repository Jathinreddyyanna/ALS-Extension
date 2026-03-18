import { useExtensionStore } from '@/store/useExtensionStore';
import { ReportForm } from '../components/ReportForm';

export const ReportTab = () => {
  const { currentUrl } = useExtensionStore();
  return <ReportForm compact url={currentUrl} />;
};
