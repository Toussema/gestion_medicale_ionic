import { NgModule } from '@angular/core';
import { PreloadAllModules, RouterModule, Routes } from '@angular/router';
import { AuthGuard } from './guards/auth.guard'; // Importez le gardien


const routes: Routes = [
  {
    path: 'home',
    loadChildren: () => import('./pages/home/home.module').then( m => m.HomePageModule)
  },
  {
    path: '',
    redirectTo: 'home',
    pathMatch: 'full'
  },
  {
    path: 'register',
    loadChildren: () => import('./pages/register/register.module').then( m => m.RegisterPageModule)
  },
  {
    path: 'login',
    loadChildren: () => import('./pages/login/login.module').then( m => m.LoginPageModule)
  },
  {
    path: 'espace-patient',
    loadChildren: () => import('./pages/espace-patient/espace-patient.module').then( m => m.EspacePatientPageModule),
    canActivate: [AuthGuard], // Appliquer le gardien
  },
  {
    path: 'espace-medecin',
    loadChildren: () => import('./pages/espace-medecin/espace-medecin.module').then( m => m.EspaceMedecinPageModule),
    canActivate: [AuthGuard], // Appliquer le gardien

  },
  {
    path: 'rendez-vous',
    loadChildren: () => import('./pages/rendez-vous/rendez-vous.module').then( m => m.RendezVousPageModule),
    canActivate: [AuthGuard], // Appliquer le gardien

  },
  {
    path: 'documents',
    loadChildren: () => import('./pages/documents/documents.module').then( m => m.DocumentsPageModule),
    canActivate: [AuthGuard], // Appliquer le gardien

  },

  {
    path: 'parametres',
    loadChildren: () => import('./pages/parametres/parametres.module').then( m => m.ParametresPageModule),
    canActivate: [AuthGuard], // Appliquer le gardien
  },
  {
    path: 'notifications-page',
    loadChildren: () => import('./pages/notifications-page/notifications-page.module').then( m => m.NotificationsPagePageModule),
    canActivate: [AuthGuard], // Appliquer le gardien
  },
];

@NgModule({
  imports: [
    RouterModule.forRoot(routes, { preloadingStrategy: PreloadAllModules })
  ],
  exports: [RouterModule]
})
export class AppRoutingModule { }
